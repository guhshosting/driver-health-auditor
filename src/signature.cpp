#include "win_raii.hpp"
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
namespace dha {
namespace {
struct TrustState {
    WINTRUST_DATA &data;
    GUID &action;
    ~TrustState() {
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &action, &data);
    }
};
} // namespace
Signature inspect_signature(const std::wstring &path) {
    Signature result;
    if (!safe_local_path(path))
        return result;
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = path.c_str();
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags =
        WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const TrustState cleanup{data, action};
    const LONG status = WinVerifyTrust(nullptr, &action, &data);
    result.status = status;
    if (status == ERROR_SUCCESS)
        result.state = "trusted_offline";
    else if (status == TRUST_E_NOSIGNATURE)
        result.state = "no_embedded_signature";
    else if (status == TRUST_E_BAD_DIGEST)
        result.state = "bad_digest";
    else if (status == TRUST_E_SUBJECT_NOT_TRUSTED || status == CERT_E_UNTRUSTEDROOT ||
             status == CERT_E_EXPIRED || status == CERT_E_REVOKED || status == CERT_E_CHAINING ||
             status == TRUST_E_EXPLICIT_DISTRUST || status == CRYPT_E_SECURITY_SETTINGS)
        result.state = "local_trust_failure";
    else
        result.state = "unavailable";
    // Trust-provider state is already acquired offline; retrieving its signer does not build a
    // chain.
    if (data.hWVTStateData) {
        const auto *provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        if (provider) {
            const auto *signer = WTHelperGetProvSignerFromChain(
                const_cast<CRYPT_PROVIDER_DATA *>(provider), 0, FALSE, 0);
            if (signer && signer->csCertChain && signer->pasCertChain[0].pCert) {
                const auto cert = signer->pasCertChain[0].pCert;
                const DWORD n =
                    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
                if (n && n < 32768) {
                    std::vector<wchar_t> b(n);
                    if (CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                           b.data(), n))
                        result.signer = b.data();
                }
            }
        }
    }
    return result;
}
} // namespace dha
