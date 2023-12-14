/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dlfcn.h>
#include <stdlib.h>
#include <time.h>

#include "aos/common/pkcs11/pkcs11.hpp"

#include "log.hpp"

namespace aos {
namespace pkcs11 {

/***********************************************************************************************************************
 * Helpers
 **********************************************************************************************************************/

Error ConvertFromPKCS11String(const Array<uint8_t>& src, String& dst)
{
    dst.Clear();

    if (src.IsEmpty()) {
        return ErrorEnum::eNone;
    }

    int size = src.Size();

    if (!dst.Resize(size).IsNone()) {
        return ErrorEnum::eNoMemory;
    }

    memcpy(dst.Get(), src.Get(), size);

    // Trim string
    for (int i = size - 1; i >= 0; --i) {
        if (dst[i] == ' ')
            --size;
        else
            break;
    }

    dst.Resize(size);

    return ErrorEnum::eNone;
}

template <size_t cSize>
Error ConvertFromPKCS11String(const CK_UTF8CHAR (&src)[cSize], String& dst)
{
    return ConvertFromPKCS11String(Array<uint8_t>(src, cSize), dst);
}

template <size_t cSize>
Error ConvertToPKCS11String(const String& src, CK_UTF8CHAR (&dst)[cSize])
{
    if (cSize <= src.Size()) {
        return ErrorEnum::eNoMemory;
    }

    memset(dst, ' ', cSize);
    memcpy(dst, src.CStr(), src.Size());

    return ErrorEnum::eNone;
}

void ConvertFromPKCS11Version(const CK_VERSION& src, Version& dst)
{
    dst.mMajor = src.major;
    dst.mMinor = src.minor;
}

CK_UTF8CHAR_PTR ConvertToPKCS11UTF8CHARPTR(const char* src)
{
    return reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(src));
}

Error ConvertFromPKCS11SlotInfo(const CK_SLOT_INFO& src, SlotInfo& dst)
{
    Error err = ConvertFromPKCS11String(src.manufacturerID, dst.mManufacturerID);
    if (!err.IsNone()) {
        return err;
    }

    err = ConvertFromPKCS11String(src.slotDescription, dst.mSlotDescription);
    if (!err.IsNone()) {
        return err;
    }

    ConvertFromPKCS11Version(src.hardwareVersion, dst.mHardwareVersion);
    ConvertFromPKCS11Version(src.firmwareVersion, dst.mFirmwareVersion);

    dst.mFlags = src.flags;

    return ErrorEnum::eNone;
}

Error ConvertFromPKCS11TokenInfo(const CK_TOKEN_INFO& src, TokenInfo& dst)
{
    Error err = ConvertFromPKCS11String(src.label, dst.mLabel);
    if (!err.IsNone()) {
        return err;
    }

    err = ConvertFromPKCS11String(src.manufacturerID, dst.mManufacturerID);
    if (!err.IsNone()) {
        return err;
    }

    err = ConvertFromPKCS11String(src.model, dst.mModel);
    if (!err.IsNone()) {
        return err;
    }

    err = ConvertFromPKCS11String(src.serialNumber, dst.mSerialNumber);
    if (!err.IsNone()) {
        return err;
    }

    dst.mFlags = src.flags;
    ConvertFromPKCS11Version(src.hardwareVersion, dst.mHardwareVersion);
    ConvertFromPKCS11Version(src.firmwareVersion, dst.mFirmwareVersion);
    dst.mTotalPublicMemory  = src.ulTotalPublicMemory;
    dst.mFreePublicMemory   = src.ulFreePublicMemory;
    dst.mTotalPrivateMemory = src.ulTotalPrivateMemory;
    dst.mFreePrivateMemory  = src.ulFreePrivateMemory;

    return ErrorEnum::eNone;
}

Error ConvertFromPKCS11LibInfo(const CK_INFO& src, LibInfo& dst)
{
    ConvertFromPKCS11Version(src.cryptokiVersion, dst.mCryptokiVersion);
    ConvertFromPKCS11Version(src.libraryVersion, dst.mLibraryVersion);

    Error err = ConvertFromPKCS11String(src.manufacturerID, dst.mManufacturerID);
    if (!err.IsNone()) {
        return err;
    }

    err = ConvertFromPKCS11String(src.libraryDescription, dst.mLibraryDescription);
    if (!err.IsNone()) {
        return err;
    }

    return ErrorEnum::eNone;
}

Error ConvertToPKCS11Attributes(const Array<ObjectAttribute>& src, Array<CK_ATTRIBUTE>& dst)
{
    if (dst.MaxSize() < src.Size()) {
        return ErrorEnum::eNoMemory;
    }

    dst.Clear();

    for (const auto& attr : src) {
        CK_ATTRIBUTE tmp;

        tmp.type       = attr.mType;
        tmp.pValue     = const_cast<uint8_t*>(attr.mValue.Get());
        tmp.ulValueLen = attr.mValue.Size();

        dst.PushBack(tmp);
    }

    return ErrorEnum::eNone;
}

Error BuildAttributes(const Array<AttributeType>& types, Array<Array<uint8_t>>& values, Array<CK_ATTRIBUTE>& dst)
{
    // number of types and values should be the same in order to be combined into attributes array.
    if (types.Size() != values.Size()) {
        return ErrorEnum::eInvalidArgument;
    }

    if (dst.MaxSize() < types.Size()) {
        return ErrorEnum::eNoMemory;
    }

    dst.Clear();

    for (size_t i = 0; i < types.Size(); ++i) {
        CK_ATTRIBUTE tmp;

        tmp.type       = types[i];
        tmp.pValue     = static_cast<void*>(values[i].Get());
        tmp.ulValueLen = values[i].MaxSize();

        dst.PushBack(tmp);
    }

    return ErrorEnum::eNone;
}

Error GetAttributesValues(Array<CK_ATTRIBUTE>& src, Array<Array<uint8_t>>& values)
{
    if (values.MaxSize() < src.Size()) {
        return ErrorEnum::eNoMemory;
    }

    values.Clear();

    for (const auto& attr : src) {
        if (attr.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
            return ErrorEnum::eInvalidArgument;
        }

        auto tmp = Array<uint8_t>(static_cast<uint8_t*>(attr.pValue), attr.ulValueLen);
        values.PushBack(tmp);
    }

    return ErrorEnum::eNone;
}

Array<uint8_t> ConvertToAttributeValue(const String& val)
{
    return {const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(val.Get())), val.Size()};
}

template <typename T>
Array<uint8_t> ConvertToAttributeValue(T& val)
{
    return {reinterpret_cast<uint8_t*>(&val), sizeof(val)};
}

/***********************************************************************************************************************
 * GenPIN
 **********************************************************************************************************************/

Error GenPIN(String& pin)
{
    if (pin.MaxSize() == 0) {
        return ErrorEnum::eNone;
    }

    pin.Clear();

    srand(::time(nullptr)); // use current time as seed for random generator

    StaticString<sizeof(unsigned) * 2> chunk;

    while (pin.Size() < pin.MaxSize()) {
        unsigned value     = rand();
        auto     byteArray = Array<uint8_t>(reinterpret_cast<uint8_t*>(&value), sizeof(value));

        chunk.Convert(byteArray);

        auto chunkSize = Min(pin.MaxSize() - pin.Size(), chunk.Size());

        pin.Insert(pin.end(), chunk.begin(), chunk.begin() + chunkSize);
    }

    return ErrorEnum::eNone;
}

/***********************************************************************************************************************
 * LibraryContext
 **********************************************************************************************************************/

LibraryContext::LibraryContext(void* handle)
    : mHandle(handle)
{
}

Error LibraryContext::Init()
{
    CK_C_GetFunctionList getFuncList = reinterpret_cast<CK_C_GetFunctionList>(dlsym(mHandle, "C_GetFunctionList"));

    if (getFuncList == nullptr) {
        LOG_ERR() << "Can't find C_GetFunctionList: dlsym err = " << dlerror();

        return ErrorEnum::eFailed;
    }

    CK_RV rv = getFuncList(&mFunctionList);
    if (rv != CKR_OK) {
        LOG_ERR() << "C_GetFunctionList failed: err = " << rv;

        return ErrorEnum::eFailed;
    }

    if (mFunctionList == nullptr) {
        LOG_ERR() << "C_GetFunctionList returned NULL";

        return ErrorEnum::eFailed;
    }

    rv = mFunctionList->C_Initialize(nullptr);
    if (rv != CKR_OK) {
        LOG_ERR() << "C_Initialize failed: err = " << rv;

        return ErrorEnum::eFailed;
    }

    return ErrorEnum::eNone;
}

Error LibraryContext::InitToken(SlotID slotID, const String& pin, const String& label)
{
    if (!mFunctionList || !mFunctionList->C_InitToken) {
        LOG_ERR() << "C_InitToken failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    CK_UTF8CHAR pkcsLabel[cLabelLen];

    auto err = ConvertToPKCS11String(label, pkcsLabel);
    if (!err.IsNone()) {
        return err;
    }

    CK_RV rv = mFunctionList->C_InitToken(slotID, ConvertToPKCS11UTF8CHARPTR(pin.CStr()), pin.Size(), pkcsLabel);
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    return ErrorEnum::eNone;
}

Error LibraryContext::GetSlotList(bool tokenPresent, Array<SlotID>& slotList) const
{
    if (!mFunctionList || !mFunctionList->C_GetSlotList) {
        LOG_ERR() << "C_GetSlotList failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    slotList.Resize(slotList.MaxSize());

    CK_ULONG count = slotList.MaxSize();

    CK_RV rv = mFunctionList->C_GetSlotList(static_cast<CK_BBOOL>(tokenPresent), slotList.Get(), &count);
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    slotList.Resize(count);

    return ErrorEnum::eNone;
}

Error LibraryContext::GetSlotInfo(SlotID slotID, SlotInfo& slotInfo) const
{
    if (!mFunctionList || !mFunctionList->C_GetSlotInfo) {
        LOG_ERR() << "C_GetSlotInfo failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    CK_SLOT_INFO pkcsInfo;

    CK_RV rv = mFunctionList->C_GetSlotInfo(slotID, &pkcsInfo);
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    return ConvertFromPKCS11SlotInfo(pkcsInfo, slotInfo);
}

Error LibraryContext::GetTokenInfo(SlotID slotID, TokenInfo& tokenInfo) const
{
    if (!mFunctionList || !mFunctionList->C_GetTokenInfo) {
        LOG_ERR() << "C_GetTokenInfo failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    CK_TOKEN_INFO pkcsInfo;

    CK_RV rv = mFunctionList->C_GetTokenInfo(slotID, &pkcsInfo);
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    return ConvertFromPKCS11TokenInfo(pkcsInfo, tokenInfo);
}

Error LibraryContext::GetLibInfo(LibInfo& libInfo) const
{
    if (!mFunctionList || !mFunctionList->C_GetInfo) {
        LOG_ERR() << "C_GetInfo failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    CK_INFO pkcsInfo;

    CK_RV rv = mFunctionList->C_GetInfo(&pkcsInfo);
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    return ConvertFromPKCS11LibInfo(pkcsInfo, libInfo);
}

RetWithError<UniquePtr<SessionContext>> LibraryContext::OpenSession(SlotID slotID, uint32_t flags)
{
    if (!mFunctionList || !mFunctionList->C_OpenSession) {
        LOG_ERR() << "C_OpenSession failed. Library is not initialized.";

        return {nullptr, ErrorEnum::eFailed};
    }

    SessionHandle handle;

    CK_RV rv = mFunctionList->C_OpenSession(slotID, flags, nullptr, nullptr, &handle);
    if (rv != CKR_OK) {
        return {nullptr, ErrorEnum::eFailed};
    }

    auto session = MakeUnique<SessionContext>(&mAllocator, handle, mFunctionList);

    return {Move(session), ErrorEnum::eNone};
}

LibraryContext::~LibraryContext()
{
    if (mFunctionList && mFunctionList->C_Finalize) {
        CK_RV rv = mFunctionList->C_Finalize(nullptr);
        if (rv != CKR_OK) {
            LOG_ERR() << "C_Finalize failed. error = " << rv;
        }
    } else {
        LOG_ERR() << "Close library failed. Library is not initialized.";
    }

    if (dlclose(mHandle) != 0) {
        LOG_ERR() << "PKCS11 library close failed: error = " << dlerror();
    }
}

/***********************************************************************************************************************
 * SessionContext
 **********************************************************************************************************************/

SessionContext::SessionContext(SessionHandle handle, CK_FUNCTION_LIST_PTR funcList)
    : mHandle(handle)
    , mFunctionList(funcList)
{
}

Error SessionContext::GetSessionInfo(SessionInfo& info) const
{
    if (!mFunctionList || !mFunctionList->C_GetSessionInfo) {
        LOG_ERR() << "C_GetSessionInfo failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    CK_RV rv = mFunctionList->C_GetSessionInfo(mHandle, &info);
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    return ErrorEnum::eNone;
}

Error SessionContext::Login(UserType userType, const String& pin)
{
    if (!mFunctionList || !mFunctionList->C_Login) {
        LOG_ERR() << "C_Login failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    CK_RV rv = mFunctionList->C_Login(mHandle, userType, ConvertToPKCS11UTF8CHARPTR(pin.CStr()), pin.Size());
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    return ErrorEnum::eNone;
}

Error SessionContext::Logout()
{
    if (!mFunctionList || !mFunctionList->C_Logout) {
        LOG_ERR() << "C_Logout failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    CK_RV rv = mFunctionList->C_Logout(mHandle);
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    return ErrorEnum::eNone;
}

Error SessionContext::InitPIN(const String& pin)
{
    if (!mFunctionList || !mFunctionList->C_InitPIN) {
        LOG_ERR() << "C_InitPIN failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    CK_RV rv = mFunctionList->C_InitPIN(mHandle, ConvertToPKCS11UTF8CHARPTR(pin.CStr()), pin.Size());
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    return ErrorEnum::eNone;
}

Error SessionContext::GetAttributeValues(
    ObjectHandle object, const Array<AttributeType>& types, Array<Array<uint8_t>>& values)
{
    if (!mFunctionList || !mFunctionList->C_GetAttributeValue) {
        LOG_ERR() << "C_GetAttributeValue failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    StaticArray<CK_ATTRIBUTE, cObjectAttributesCount> pkcsAttributes;

    Error err = BuildAttributes(types, values, pkcsAttributes);
    if (!err.IsNone()) {
        return err;
    }

    CK_RV rv = mFunctionList->C_GetAttributeValue(mHandle, object, pkcsAttributes.Get(), pkcsAttributes.Size());
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    return GetAttributesValues(pkcsAttributes, values);
}

Error SessionContext::FindObjects(const Array<ObjectAttribute>& templ, Array<ObjectHandle>& objects)
{
    Error initErr = FindObjectsInit(templ);
    if (!initErr.IsNone()) {
        return initErr;
    }

    Error findErr    = FindObjects(objects);
    Error finalError = FindObjectsFinal();

    if (!findErr.IsNone()) {
        return findErr;
    }

    if (!finalError.IsNone()) {
        return finalError;
    }

    return ErrorEnum::eNone;
}

RetWithError<ObjectHandle> SessionContext::CreateObject(const Array<ObjectAttribute>& templ)
{
    if (!mFunctionList || !mFunctionList->C_CreateObject) {
        LOG_ERR() << "C_CreateObject failed. Library is not initialized.";

        return {0, ErrorEnum::eFailed};
    }

    StaticArray<CK_ATTRIBUTE, cObjectAttributesCount> pkcsTempl;

    Error err = ConvertToPKCS11Attributes(templ, pkcsTempl);
    if (!err.IsNone()) {
        return {0, err};
    }

    ObjectHandle objHandle = CK_INVALID_HANDLE;

    CK_RV rv = mFunctionList->C_CreateObject(mHandle, pkcsTempl.Get(), pkcsTempl.Size(), &objHandle);
    if (rv != CKR_OK) {
        return {0, ErrorEnum::eFailed};
    }

    return {objHandle, ErrorEnum::eNone};
}

Error SessionContext::DestroyObject(ObjectHandle object)
{
    if (!mFunctionList || !mFunctionList->C_DestroyObject) {
        LOG_ERR() << "C_DestroyObject failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    CK_RV rv = mFunctionList->C_DestroyObject(mHandle, object);
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    return ErrorEnum::eNone;
}

SessionHandle SessionContext::GetHandle() const
{
    return mHandle;
}

CK_FUNCTION_LIST_PTR SessionContext::GetFunctionList() const
{
    return mFunctionList;
}

SessionContext::~SessionContext()
{
    if (!mFunctionList || !mFunctionList->C_CloseSession) {
        LOG_ERR() << "C_CloseSession failed. Library is not initialized.";

        return;
    }

    CK_RV rv = mFunctionList->C_CloseSession(mHandle);
    if (rv != CKR_OK) {
        LOG_ERR() << "C_CloseSession failed. error = " << rv;
    }
}

Error SessionContext::FindObjectsInit(const Array<ObjectAttribute>& templ)
{
    if (!mFunctionList || !mFunctionList->C_FindObjectsInit) {
        LOG_ERR() << "C_FindObjectsInit failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    StaticArray<CK_ATTRIBUTE, cObjectAttributesCount> pkcsTempl;

    Error err = ConvertToPKCS11Attributes(templ, pkcsTempl);
    if (!err.IsNone()) {
        return err;
    }

    CK_RV rv = mFunctionList->C_FindObjectsInit(mHandle, pkcsTempl.Get(), pkcsTempl.Size());
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    return ErrorEnum::eNone;
}

Error SessionContext::FindObjects(Array<ObjectHandle>& objects)
{
    if (!mFunctionList || !mFunctionList->C_FindObjects) {
        LOG_ERR() << "C_FindObjects failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    size_t foundObjectsCount = 0, chunk = 0;

    objects.Resize(objects.MaxSize());

    while (true) {
        if (foundObjectsCount == objects.MaxSize()) {
            return ErrorEnum::eNoMemory;
        }

        CK_RV rv = mFunctionList->C_FindObjects(
            mHandle, objects.begin() + foundObjectsCount, objects.MaxSize() - foundObjectsCount, &chunk);
        if (rv != CKR_OK) {
            return ErrorEnum::eFailed;
        }

        foundObjectsCount += chunk;

        // success only when we ensured that all objects found
        if (chunk == 0) {
            objects.Resize(foundObjectsCount);

            return ErrorEnum::eNone;
        }
    }

    return ErrorEnum::eFailed;
}

Error SessionContext::FindObjectsFinal()
{
    if (!mFunctionList || !mFunctionList->C_FindObjectsFinal) {
        LOG_ERR() << "C_FindObjectsFinal failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    CK_RV rv = mFunctionList->C_FindObjectsFinal(mHandle);
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    return ErrorEnum::eNone;
}

RetWithError<PrivateKey> Utils::exportPrivateKey(
    ObjectHandle privKeyHandle, ObjectHandle pubKeyHandle, CK_KEY_TYPE keyType)
{
    switch (keyType) {
    case CKK_RSA: {
        StaticArray<Array<uint8_t>, cObjectAttributesCount> attrValues;
        StaticArray<AttributeType, cObjectAttributesCount>  attrTypes;

        attrTypes.PushBack(CKA_MODULUS);
        attrTypes.PushBack(CKA_PUBLIC_EXPONENT);

        StaticArray<uint8_t, crypto::cRSAModulusSize>     n;
        StaticArray<uint8_t, crypto::cRSAPubExponentSize> e;

        attrValues.PushBack(n);
        attrValues.PushBack(e);

        auto err = mSession.GetAttributeValues(pubKeyHandle, attrTypes, attrValues);
        if (!err.IsNone()) {
            return {{}, err};
        }

        auto cryptoKey
            = MakeShared<crypto::RSAPrivateKey>(&mAllocator, crypto::RSAPublicKey(attrValues[0], attrValues[1]));
        PrivateKey pkcsKey = {privKeyHandle, pubKeyHandle, cryptoKey};

        return {pkcsKey, ErrorEnum::eNone};
    }

    case CKK_ECDSA: {
        StaticArray<Array<uint8_t>, cObjectAttributesCount> attrValues;
        StaticArray<AttributeType, cObjectAttributesCount>  attrTypes;

        attrTypes.PushBack(CKA_ECDSA_PARAMS);
        attrTypes.PushBack(CKA_EC_POINT);

        StaticArray<uint8_t, crypto::cECDSAParamsOIDSize> params;
        StaticArray<uint8_t, crypto::cECDSAPointDERSize>  point;

        attrValues.PushBack(params);
        attrValues.PushBack(point);

        auto err = mSession.GetAttributeValues(pubKeyHandle, attrTypes, attrValues);
        if (!err.IsNone()) {
            return {{}, err};
        }

        auto cryptoKey
            = MakeShared<crypto::ECDSAPrivateKey>(&mAllocator, crypto::ECDSAPublicKey(attrValues[0], attrValues[1]));
        PrivateKey pkcsKey = {privKeyHandle, pubKeyHandle, cryptoKey};

        return {pkcsKey, ErrorEnum::eNone};
    }
    }

    return {{}, ErrorEnum::eInvalidArgument};
}

/***********************************************************************************************************************
 * PKCS11Manager
 **********************************************************************************************************************/

SharedPtr<LibraryContext> PKCS11Manager::OpenLibrary(const String& library)
{
    LOG_INF() << "Loading library. path = " << library;

    for (auto& lib : mLibraries) {
        if (lib.mFirst == library) {
            return lib.mSecond;
        }
    }

    if (mLibraries.MaxSize() == mLibraries.Size()) {
        return nullptr;
    }

    dlerror(); // clean previous error status

    void* handle = dlopen(library.CStr(), RTLD_NOW);
    if (handle == nullptr) {
        LOG_ERR() << "Can't open PKCS11 library: path = " << library << ", err = " << dlerror();

        return nullptr;
    }

    auto res = MakeShared<LibraryContext>(&mAllocator, handle);
    if (!res || !res->Init().IsNone()) {
        return nullptr;
    }

    mLibraries.EmplaceBack(library, res);

    return res;
}

/***********************************************************************************************************************
 * Utils
 **********************************************************************************************************************/

Utils::Utils(SessionContext& session, Allocator& allocator)
    : mSession(session)
    , mAllocator(allocator)
{
}

RetWithError<PrivateKey> Utils::GenerateRSAKeyPairWithLabel(
    const Array<uint8_t>& id, const String& label, unsigned long bitsCount)
{
    auto funcList = mSession.GetFunctionList();

    if (!funcList || !funcList->C_GenerateKeyPair) {
        LOG_ERR() << "C_GenerateKeyPair failed. Library is not initialized.";

        return {{}, ErrorEnum::eFailed};
    }

    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE     keyTypeRSA  = CKK_RSA;
    CK_BBOOL        trueVal     = CK_TRUE;
    CK_BBOOL        falseVal    = CK_FALSE;
    CK_BYTE         publicExp[] = {1, 0, 1};
    CK_ULONG        modulusBits = bitsCount;

    StaticArray<CK_ATTRIBUTE, cObjectAttributesCount> pubKeyTempl;
    StaticArray<CK_ATTRIBUTE, cObjectAttributesCount> privKeyTempl;

    pubKeyTempl.PushBack({CKA_CLASS, &pubKeyClass, sizeof(pubKeyClass)});
    pubKeyTempl.PushBack({CKA_KEY_TYPE, &keyTypeRSA, sizeof(keyTypeRSA)});
    pubKeyTempl.PushBack({CKA_TOKEN, &trueVal, sizeof(trueVal)});
    pubKeyTempl.PushBack({CKA_VERIFY, &trueVal, sizeof(trueVal)});
    pubKeyTempl.PushBack({CKA_ENCRYPT, &trueVal, sizeof(trueVal)});
    pubKeyTempl.PushBack({CKA_PUBLIC_EXPONENT, publicExp, sizeof(publicExp)});
    pubKeyTempl.PushBack({CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)});
    pubKeyTempl.PushBack({CKA_ID, const_cast<uint8_t*>(id.Get()), id.Size()});
    pubKeyTempl.PushBack({CKA_LABEL, const_cast<char*>(label.Get()), label.Size()});

    privKeyTempl.PushBack({CKA_TOKEN, &trueVal, sizeof(trueVal)});
    privKeyTempl.PushBack({CKA_SIGN, &trueVal, sizeof(trueVal)});
    privKeyTempl.PushBack({CKA_DECRYPT, &trueVal, sizeof(trueVal)});
    privKeyTempl.PushBack({CKA_SENSITIVE, &trueVal, sizeof(trueVal)});
    privKeyTempl.PushBack({CKA_EXTRACTABLE, &falseVal, sizeof(falseVal)});
    privKeyTempl.PushBack({CKA_ID, const_cast<uint8_t*>(id.Get()), id.Size()});
    privKeyTempl.PushBack({CKA_LABEL, const_cast<char*>(label.Get()), label.Size()});

    CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};

    ObjectHandle privKeyHandle = CK_INVALID_HANDLE;
    ObjectHandle pubKeyHandle  = CK_INVALID_HANDLE;

    CK_RV rv = funcList->C_GenerateKeyPair(mSession.GetHandle(), &mechanism, pubKeyTempl.Get(), pubKeyTempl.Size(),
        privKeyTempl.Get(), privKeyTempl.Size(), &pubKeyHandle, &privKeyHandle);

    if (rv != CKR_OK) {
        return {{}, ErrorEnum::eFailed};
    }

    return exportPrivateKey(privKeyHandle, pubKeyHandle, keyTypeRSA);
}

RetWithError<PrivateKey> Utils::GenerateECDSAKeyPairWithLabel(
    const Array<uint8_t>& id, const String& label, EllipticCurve curve)
{
    // only P384 curve is supported for now
    assert(curve == EllipticCurve::eP384);

    auto funcList = mSession.GetFunctionList();

    if (!funcList || !funcList->C_GenerateKeyPair) {
        LOG_ERR() << "C_GenerateKeyPair failed. Library is not initialized.";

        return {{}, ErrorEnum::eFailed};
    }

    CK_OBJECT_CLASS pubKeyClass  = CKO_PUBLIC_KEY;
    CK_KEY_TYPE     keyTypeECDSA = CKK_ECDSA;
    CK_BBOOL        trueVal      = CK_TRUE;
    CK_BBOOL        falseVal     = CK_FALSE;

    static uint8_t cP384OID[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};

    StaticArray<CK_ATTRIBUTE, cObjectAttributesCount> pubKeyTempl;
    StaticArray<CK_ATTRIBUTE, cObjectAttributesCount> privKeyTempl;

    pubKeyTempl.PushBack({CKA_CLASS, &pubKeyClass, sizeof(pubKeyClass)});
    pubKeyTempl.PushBack({CKA_KEY_TYPE, &keyTypeECDSA, sizeof(keyTypeECDSA)});
    pubKeyTempl.PushBack({CKA_TOKEN, &trueVal, sizeof(trueVal)});
    pubKeyTempl.PushBack({CKA_VERIFY, &trueVal, sizeof(trueVal)});
    pubKeyTempl.PushBack({CKA_ECDSA_PARAMS, cP384OID, sizeof(cP384OID)});
    pubKeyTempl.PushBack({CKA_ID, const_cast<uint8_t*>(id.Get()), id.Size()});
    pubKeyTempl.PushBack({CKA_LABEL, const_cast<char*>(label.Get()), label.Size()});

    privKeyTempl.PushBack({CKA_TOKEN, &trueVal, sizeof(trueVal)});
    privKeyTempl.PushBack({CKA_SIGN, &trueVal, sizeof(trueVal)});
    privKeyTempl.PushBack({CKA_SENSITIVE, &trueVal, sizeof(trueVal)});
    privKeyTempl.PushBack({CKA_EXTRACTABLE, &falseVal, sizeof(falseVal)});
    privKeyTempl.PushBack({CKA_ID, const_cast<uint8_t*>(id.Get()), id.Size()});
    privKeyTempl.PushBack({CKA_LABEL, const_cast<char*>(label.Get()), label.Size()});

    CK_MECHANISM mechanism = {CKM_ECDSA_KEY_PAIR_GEN, nullptr, 0};

    ObjectHandle privKeyHandle = CK_INVALID_HANDLE;
    ObjectHandle pubKeyHandle  = CK_INVALID_HANDLE;

    CK_RV rv = funcList->C_GenerateKeyPair(mSession.GetHandle(), &mechanism, pubKeyTempl.Get(), pubKeyTempl.Size(),
        privKeyTempl.Get(), privKeyTempl.Size(), &pubKeyHandle, &privKeyHandle);

    if (rv != CKR_OK) {
        return {{}, ErrorEnum::eFailed};
    }

    return exportPrivateKey(privKeyHandle, pubKeyHandle, keyTypeECDSA);
}

RetWithError<PrivateKey> Utils::FindPrivateKey(const Array<uint8_t>& id, const String& label)
{
    constexpr auto cSingleAttribute = 1;

    CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS pubKeyClass  = CKO_PUBLIC_KEY;

    StaticArray<ObjectAttribute, cObjectAttributesCount> privKeyTempl;

    privKeyTempl.PushBack({CKA_CLASS, ConvertToAttributeValue(privKeyClass)});
    privKeyTempl.PushBack({CKA_ID, id});
    privKeyTempl.PushBack({CKA_LABEL, ConvertToAttributeValue(label)});

    StaticArray<ObjectHandle, cKeysPerToken> privKeys;

    auto err = mSession.FindObjects(privKeyTempl, privKeys);
    if (!err.IsNone()) {
        return {{}, err};
    }

    // Find public part with matching attributes: id, label & key type.
    StaticArray<AttributeType, cSingleAttribute> keyTypeAttribute;

    keyTypeAttribute.PushBack(CKA_KEY_TYPE);

    CK_KEY_TYPE                                          keyType;
    StaticArray<Array<uint8_t>, cSingleAttribute>        keyTypeValue;
    StaticArray<ObjectAttribute, cObjectAttributesCount> pubKeyTempl;

    keyTypeValue.PushBack(ConvertToAttributeValue(keyType));

    pubKeyTempl.PushBack({CKA_CLASS, ConvertToAttributeValue(pubKeyClass)});
    pubKeyTempl.PushBack({CKA_ID, id});
    pubKeyTempl.PushBack({CKA_LABEL, ConvertToAttributeValue(label)});
    pubKeyTempl.PushBack({CKA_KEY_TYPE, ConvertToAttributeValue(keyType)});

    StaticArray<ObjectHandle, cKeysPerToken> pubKeys;

    for (const auto& privKey : privKeys) {
        err = mSession.GetAttributeValues(privKey, keyTypeAttribute, keyTypeValue);
        if (!err.IsNone()) {
            return {{}, err};
        }

        err = mSession.FindObjects(pubKeyTempl, pubKeys);
        if (!err.IsNone()) {
            return {{}, err};
        }

        if (pubKeys.IsEmpty()) {
            continue;
        }

        return exportPrivateKey(privKey, pubKeys[0], keyType);
    }

    return {{}, ErrorEnum::eNotFound};
}

Error Utils::DeletePrivateKey(const PrivateKey& key)
{
    auto err = mSession.DestroyObject(key.GetPrivHandle());
    if (!err.IsNone()) {
        return err;
    }

    return mSession.DestroyObject(key.GetPubHandle());
}

Error Utils::ImportCertificate(const Array<uint8_t>& id, const String& label, const crypto::x509::Certificate& cert)
{
    auto funcList = mSession.GetFunctionList();

    if (!funcList || !funcList->C_CreateObject) {
        LOG_ERR() << "C_CreateObject failed. Library is not initialized.";

        return ErrorEnum::eFailed;
    }

    CK_OBJECT_CLASS     certClass    = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certTypeX509 = CKC_X_509;
    CK_BBOOL            trueVal      = CK_TRUE;
    CK_BBOOL            falseVal     = CK_FALSE;

    StaticArray<uint8_t, crypto::cSerialNumSize> serialNum;

    auto err = crypto::asn1::EncodeBigInt(cert.mSerial, serialNum);
    if (!err.IsNone()) {
        return err;
    }

    StaticArray<CK_ATTRIBUTE, cObjectAttributesCount> certTempl;

    certTempl.PushBack({CKA_CLASS, &certClass, sizeof(certClass)});
    certTempl.PushBack({CKA_CERTIFICATE_TYPE, &certTypeX509, sizeof(certTypeX509)});
    certTempl.PushBack({CKA_TOKEN, &trueVal, sizeof(trueVal)});
    certTempl.PushBack({CKA_PRIVATE, &falseVal, sizeof(falseVal)});
    certTempl.PushBack({CKA_SUBJECT, const_cast<uint8_t*>(cert.mSubject.Get()), cert.mSubject.Size()});
    certTempl.PushBack({CKA_ISSUER, const_cast<uint8_t*>(cert.mIssuer.Get()), cert.mIssuer.Size()});
    certTempl.PushBack({CKA_SERIAL_NUMBER, serialNum.Get(), serialNum.Size()});
    certTempl.PushBack({CKA_VALUE, const_cast<uint8_t*>(cert.mRaw.Get()), cert.mRaw.Size()});
    certTempl.PushBack({CKA_ID, const_cast<uint8_t*>(id.Get()), id.Size()});
    certTempl.PushBack({CKA_LABEL, const_cast<char*>(label.Get()), label.Size()});

    ObjectHandle certHandle = CK_INVALID_HANDLE;

    CK_RV rv = funcList->C_CreateObject(mSession.GetHandle(), certTempl.Get(), certTempl.Size(), &certHandle);
    if (rv != CKR_OK) {
        return ErrorEnum::eFailed;
    }

    return ErrorEnum::eNone;
}

RetWithError<bool> Utils::HasCertificate(const Array<uint8_t>& issuer, const Array<uint8_t>& serialNumber)
{
    static constexpr auto cSingleObject = 1;

    CK_OBJECT_CLASS                              certClass = CKO_CERTIFICATE;
    StaticArray<uint8_t, crypto::cSerialNumSize> asn1SerialNum;

    auto err = crypto::asn1::EncodeBigInt(serialNumber, asn1SerialNum);
    if (!err.IsNone()) {
        return {false, err};
    }

    StaticArray<ObjectAttribute, cObjectAttributesCount> certTempl;
    certTempl.PushBack({CKA_CLASS, ConvertToAttributeValue(certClass)});
    certTempl.PushBack({CKA_ISSUER, issuer});
    certTempl.PushBack({CKA_SERIAL_NUMBER, asn1SerialNum});

    StaticArray<ObjectHandle, cSingleObject> certHandles;

    err = mSession.FindObjects(certTempl, certHandles);
    // "not enough memory" treat as success and certificate found
    if (err.Is(ErrorEnum::eNoMemory)) {
        return {true, ErrorEnum::eNone};
    }

    if (!err.IsNone()) {
        return {false, err};
    }

    return {!certHandles.IsEmpty(), ErrorEnum::eNone};
}

Error Utils::DeleteCertificate(const Array<uint8_t>& id, const String& label)
{
    CK_OBJECT_CLASS                              certClass = CKO_CERTIFICATE;
    StaticArray<uint8_t, crypto::cSerialNumSize> asn1SerialNum;

    StaticArray<ObjectAttribute, cObjectAttributesCount> certTempl;

    certTempl.PushBack({CKA_CLASS, ConvertToAttributeValue(certClass)});
    certTempl.PushBack({CKA_ID, id});
    certTempl.PushBack({CKA_LABEL, ConvertToAttributeValue(label)});

    StaticArray<ObjectHandle, cKeysPerToken> certHandles;

    auto err = mSession.FindObjects(certTempl, certHandles);
    if (!err.IsNone()) {
        return err;
    }

    for (const auto handle : certHandles) {
        err = mSession.DestroyObject(handle);
        if (!err.IsNone()) {
            return err;
        }
    }

    return ErrorEnum::eNone;
}

Error Utils::ConvertPKCS11String(const Array<uint8_t>& src, String& dst)
{
    return ConvertFromPKCS11String(src, dst);
}

} // namespace pkcs11
} // namespace aos