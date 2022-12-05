#pragma once
#include <windows.h>
#include <stdio.h>
#include <comutil.h>
#include <netfw.h>


extern "C" DECLSPEC_IMPORT HRESULT  WINAPI  OLE32$CoCreateInstance (REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
extern "C" DECLSPEC_IMPORT HRESULT  WINAPI  OLE32$CoInitializeEx (LPVOID pvReserved, DWORD dwCoInit);
extern "C" DECLSPEC_IMPORT HRESULT  WINAPI  OLE32$CoSetProxyBlanket(IUnknown* pProxy, DWORD dwAuthnSvc, DWORD dwAuthzSvc, OLECHAR* pServerPrincName, DWORD dwAuthnLevel, DWORD dwImpLevel, RPC_AUTH_IDENTITY_HANDLE pAuthInfo, DWORD dwCapabilities);
extern "C" DECLSPEC_IMPORT void     WINAPI  OLE32$CoUninitialize (void);
extern "C" DECLSPEC_IMPORT HRESULT  WINAPI  OLE32$CoInitializeSecurity (PSECURITY_DESCRIPTOR pSecDesc, LONG cAuthSvc, SOLE_AUTHENTICATION_SERVICE *asAuthSvc, void *pReserved1, DWORD dwAuthnLevel, DWORD dwImpLevel, void *pAuthList, DWORD dwCapabilities, void *pReserved3);
extern "C" DECLSPEC_IMPORT BSTR	    WINAPI  OLEAUT32$SysAllocString(const OLECHAR *);
extern "C" DECLSPEC_IMPORT void	    WINAPI  OLEAUT32$SysFreeString(BSTR);
extern "C" DECLSPEC_IMPORT UINT	    WINAPI  OLEAUT32$SysStringLen(BSTR);
extern "C" DECLSPEC_IMPORT HRESULT  WINAPI  OLEAUT32$VariantChangeType(VARIANTARG *pvargDest,VARIANTARG *pvarSrc,USHORT wFlags,VARTYPE vt);
extern "C" DECLSPEC_IMPORT HRESULT  WINAPI  OLEAUT32$VariantClear(VARIANTARG *pvarg);
extern "C" DECLSPEC_IMPORT void     WINAPI  OLEAUT32$VariantInit(VARIANTARG *pvarg);
extern "C" DECLSPEC_IMPORT int      WINAPI  SHLWAPI$StrCmpW (PCWSTR psz1, PCWSTR psz2);
extern "C" DECLSPEC_IMPORT PCWSTR   WINAPI  SHLWAPI$StrStrW (PCWSTR pszFirst, PCWSTR pszSrch);
extern "C" DECLSPEC_IMPORT void     WINAPI  OLEAUT32$SafeArrayDestroy(SAFEARRAY *psa);
extern "C" DECLSPEC_IMPORT HRESULT	WINAPI  OLEAUT32$SafeArrayLock(SAFEARRAY *psa);
extern "C" DECLSPEC_IMPORT HRESULT	WINAPI  OLEAUT32$SafeArrayGetLBound(SAFEARRAY *psa, UINT nDim, LONG *plLbound);
extern "C" DECLSPEC_IMPORT HRESULT	WINAPI  OLEAUT32$SafeArrayGetUBound(SAFEARRAY *psa, UINT nDim, LONG *plUbound);
extern "C" DECLSPEC_IMPORT HRESULT	WINAPI  OLEAUT32$SafeArrayGetElement(SAFEARRAY *psa, LONG *rgIndices, void *pv);
extern "C" DECLSPEC_IMPORT UINT	    WINAPI  OLEAUT32$SafeArrayGetElemsize(SAFEARRAY *psa);
extern "C" DECLSPEC_IMPORT HRESULT	WINAPI  OLEAUT32$SafeArrayAccessData(SAFEARRAY *psa,void HUGEP **ppvData);
extern "C" DECLSPEC_IMPORT HRESULT	WINAPI  OLEAUT32$SafeArrayUnaccessData(SAFEARRAY *psa);

extern "C" {
    static GUID g_CLSID_WbemLocator = { 0x4590f811, 0x1d3a, 0x11d0, { 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };
    static GUID g_IID_IWbemLocator   = { 0xdc12a687, 0x737f, 0x11cf, { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };
}