/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_PKCS11_HPP_
#define AOS_PKCS11_HPP_

#include "aos/common/pkcs11/cryptoki/pkcs11.h"

#include "aos/common/crypto.hpp"

#include "aos/common/tools/log.hpp"
#include "aos/common/tools/memory.hpp"
#include "aos/common/tools/utils.hpp"

namespace aos {
namespace pkcs11 {

/**
 * Maximum length of PKCS11 slot description.
 */
constexpr auto cSlotDescriptionLen = AOS_CONFIG_PKCS11_SLOT_DESCRIPTION_LEN;

/**
 * Maximum length of PKCS11 manufacture ID.
 */
constexpr auto cManufacturerIDLen = AOS_CONFIG_PKCS11_MANUFACTURE_ID_LEN;

/**
 * Maximum length of PKCS11 token label.
 */
constexpr auto cLabelLen = AOS_CONFIG_PKCS11_LABEL_LEN;

/**
 * Library description length.
 */
constexpr auto cLibraryDescLen = AOS_CONFIG_PKCS11_LIBRARY_DESC_LEN;

/**
 * HSM device model length.
 */
constexpr auto cModelLen = AOS_CONFIG_PKCS11_MODEL_LEN;

/**
 * Maximum length of user PIN (password).
 */
constexpr auto cPINLength = AOS_CONFIG_PKCS11_PIN_LEN;

/**
 * The types of Cryptoki users.
 */
using UserType = CK_USER_TYPE;

/**
 * Cryptoki state type.
 */
using State = CK_STATE;

/**
 * Cryptoki flags type.
 */
using Flags = CK_FLAGS;

/**
 * A Cryptoki-assigned value that identifies a session.
 */
using SessionHandle = CK_SESSION_HANDLE;

/**
 * A Cryptoki-assigned value that identifies an attribute type.
 */
using AttributeType = CK_ATTRIBUTE_TYPE;

/**
 * Cryptoki object handles.
 */
using ObjectHandle = CK_OBJECT_HANDLE;

/**
 * Cryptoki object class.
 */
using ObjectClass = CK_OBJECT_CLASS;

/**
 * A Cryptoki-assigned value that identifies a slot.
 */
using SlotID = CK_SLOT_ID;

/**
 * Generates random unique PIN.
 *
 * @param[out] pin result pin.
 * @return Error.
 */
inline Error GenPIN(String& pin)
{
    (void)pin;

    return ErrorEnum::eNone;
}

/**
 * Any version information related to PKCS11 library.
 */
struct Version {
    uint8_t mMajor;
    uint8_t mMinor;

    /**
     * Prints object to log.
     *
     * @param log log to output.
     * @param version object instance.
     * @return Log&.
     */
    friend Log& operator<<(Log& log, const Version& version)
    {
        log << static_cast<int>(version.mMajor) << "." << static_cast<int>(version.mMinor);
        return log;
    }
};

/**
 * Information about Cryptoki library.
 * https://www.cryptsoft.com/pkcs11doc/v200/structCK__INFO.html
 */
struct LibInfo {
    /**
     * Cryptoki interface version number.
     */
    Version mCryptokiVersion;
    /**
     * Cryptoki library version number.
     */
    Version mLibraryVersion;
    /**
     * ID of the Cryptoki library manufacturer.
     */
    StaticString<cManufacturerIDLen> mManufacturerID;
    /**
     * Description of the library.
     */
    StaticString<cLibraryDescLen> mLibraryDescription;

    /**
     * Prints object to log.
     *
     * @param log log to output.
     * @param libInfo object instance.
     * @return Log&.
     */
    friend Log& operator<<(Log& log, const LibInfo& libInfo)
    {
        log << "{cryptokiVersion = " << libInfo.mCryptokiVersion << ", libraryVersion = " << libInfo.mLibraryVersion
            << ", manufacturer = " << libInfo.mManufacturerID << ", description = " << libInfo.mLibraryDescription
            << "}";
        return log;
    }
};

/**
 * Information about PKCS11 slot info.
 * https://www.cryptsoft.com/pkcs11doc/v210/group__SEC__9__2__SLOT__AND__TOKEN__TYPES.html
 */
struct SlotInfo {
    /**
     * ID of the device manufacturer.
     */
    StaticString<cManufacturerIDLen> mManufacturerID;
    /**
     * Description of the slot.
     */
    StaticString<cSlotDescriptionLen> mSlotDescription;
    /**
     * Bit flags that provide capabilities of the slot.
     */
    Flags mFlags;
    /**
     * Version of the slot's hardware.
     */
    Version mHardwareVersion;
    /**
     * Version of the slot's firmware.
     */
    Version mFirmwareVersion;

    /**
     * Prints object to log.
     *
     * @param log log to output.
     * @param slotInfo object instance.
     * @return Log&.
     */
    friend Log& operator<<(Log& log, const SlotInfo& slotInfo)
    {
        log << "{manufacturer = " << slotInfo.mManufacturerID << ", description = " << slotInfo.mSlotDescription
            << ", hwVersion = " << slotInfo.mHardwareVersion << ", fwVersion = " << slotInfo.mFirmwareVersion
            << ", flags = " << slotInfo.mFlags << "}";
        return log;
    }
};

/**
 * Information about session.
 */
using SessionInfo = CK_SESSION_INFO;

/**
 * Information about PKCS11 token.
 */
struct TokenInfo {
    /**
     * Application-defined label, assigned during token initialization.
     */
    StaticString<cLabelLen> mLabel;
    /**
     * ID of the device manufacturer.
     */
    StaticString<cManufacturerIDLen> mManufacturerID;
    /**
     * HSM device model.
     */
    StaticString<cModelLen> mModel;
    /**
     * HSM device serial number.
     */
    StaticString<crypto::cSerialNumStrLen> mSerialNumber;
    /**
     * Bit flags indicating capabilities and status of the device.
     */
    Flags mFlags;
    /**
     * Version number of hardware.
     */
    Version mHardwareVersion;
    /**
     * Version number of firmware.
     */
    Version mFirmwareVersion;
    /**
     * The total amount of memory on the token in bytes in which public objects may be stored.
     */
    size_t mTotalPublicMemory;
    /**
     * The amount of free (unused) memory on the token in bytes for public objects.
     */
    size_t mFreePublicMemory;
    /**
     * The total amount of memory on the token in bytes in which private objects may be stored.
     */
    size_t mTotalPrivateMemory;
    /**
     * The amount of free (unused) memory on the token in bytes for private objects.
     */
    size_t mFreePrivateMemory;

    /**
     * Prints object to log.
     *
     * @param log log to output.
     * @param tokenInfo object instance.
     * @return Log&.
     */
    friend Log& operator<<(Log& log, const TokenInfo& tokenInfo)
    {
        log << "{label = " << tokenInfo.mLabel << ", manufacturer = " << tokenInfo.mManufacturerID
            << ", model = " << tokenInfo.mModel << ", serial = " << tokenInfo.mSerialNumber
            << ", hwVersion = " << tokenInfo.mHardwareVersion << ", fwVersion = " << tokenInfo.mFirmwareVersion
            << ", publicMemory = " << tokenInfo.mTotalPublicMemory - tokenInfo.mFreePublicMemory << "/"
            << tokenInfo.mTotalPublicMemory
            << ", privateMemory = " << tokenInfo.mTotalPrivateMemory - tokenInfo.mFreePrivateMemory << "/"
            << tokenInfo.mTotalPrivateMemory << ", flags = " << tokenInfo.mFlags << "}";
        return log;
    }
};

/**
 * Object attribute.
 */
struct ObjectAttribute {

    /**
     * Object constructor.
     */
    ObjectAttribute(AttributeType type, const Array<uint8_t>& value)
        : mType(type)
        , mValue(value)
    {
    }

    /**
     * Attribute type.
     */
    AttributeType mType;
    /**
     * Attribute value.
     */
    Array<uint8_t> mValue;
};

/**
 * Encapsulates session-related routines of Cryptoki API.
 */
class SessionContext {
public:
    /**
     * Returns session information.
     *
     * @param[out] info result information.
     * @return Error.
     */
    Error GetSessionInfo(SessionInfo& info) const
    {
        (void)info;

        return {};
    }

    /**
     * Logs a user into a token.
     *
     * @param userType type of Cryptoki user.
     * @param pin user’s PIN.
     * @return Error.
     */
    Error Login(UserType userType, const String& pin)
    {
        (void)userType;
        (void)pin;

        return {};
    }

    /**
     * Logs a user out from a token.
     *
     * @return Error.
     */
    Error Logout() { return {}; }

    /**
     * Initializes the normal user's PIN.
     *
     * @param pin user pin.
     * @return Error.
     */
    Error InitPIN(const String& pin)
    {
        (void)pin;

        return {};
    }

    /**
     * Obtains an attribute values of the specified object.
     *
     * @param handle object handle.
     * @param types types of attributes to be returned.
     * @param[out] values result attribute values.
     * @return Error.
     */
    Error GetAttributeValues(ObjectHandle handle, const Array<AttributeType>& types, Array<Array<uint8_t>>& values)
    {
        (void)handle;
        (void)types;
        (void)values;

        return {};
    }

    /**
     * Searches for token and session objects that match a template.
     *
     * @param templ template for search operation.
     * @param[out] objects result object handles.
     * @return Error.
     */
    Error FindObjects(const Array<ObjectAttribute>& templ, Array<ObjectHandle>& objects)
    {
        (void)templ;
        (void)objects;

        return {};
    }

    /**
     * Creates a new object.
     *
     * @param templ object’s template.
     * @return RetWithError<ObjectHandle>.
     */
    RetWithError<ObjectHandle> CreateObject(const Array<ObjectAttribute>& templ)
    {
        (void)templ;

        return {0, ErrorEnum::eNone};
    }

    /**
     * Destroys object by its handle.
     *
     * @param handle handle of the object to be destroyed.
     * @return Error.
     */
    Error DestroyObject(ObjectHandle handle)
    {
        (void)handle;

        return {};
    }

    /**
     * Returns session handle.
     *
     * @return session handle.
     */
    SessionHandle GetHandle() const { return {}; }

    /**
     * Destroys object instance.
     */
    ~SessionContext() = default;
};

/**
 * PKCS11 Context instance.
 */
class LibraryContext {
public:
    /**
     * Initializes a token.
     *
     * @param slotID slot identifier.
     * @param pin user pin.
     * @param label token label.
     * @return Error.
     */
    Error InitToken(pkcs11::SlotID slotID, const String& pin, const String& label)
    {
        (void)slotID;
        (void)pin;
        (void)label;

        return {};
    }

    /**
     * Returns list of slots in the system.
     *
     * @param tokenPresent
     * @param[out] slotList result slot list.
     * @return Error.
     */
    Error GetSlotList(bool tokenPresent, Array<pkcs11::SlotID>& slotList) const
    {
        (void)tokenPresent;
        (void)slotList;

        return {};
    }

    /**
     * Returns information about slot.
     *
     * @param slotID slot id.
     * @param[out] slotInfo result slot information.
     * @return Error.
     */
    Error GetSlotInfo(pkcs11::SlotID slotID, SlotInfo& slotInfo) const
    {
        (void)slotID;
        (void)slotInfo;

        return {};
    }

    /**
     * Returns token information for the specified slot id.
     *
     * @param slotID slot id.
     * @param[out] tokenInfo token information for the slot.
     * @return Error.
     */
    Error GetTokenInfo(pkcs11::SlotID slotID, TokenInfo& tokenInfo) const
    {
        (void)slotID;
        (void)tokenInfo;

        return {};
    }

    /**
     * Returns general information about Cryptoki library.
     *
     * @param[out] libInfo result information.
     * @return Error.
     */
    Error GetLibInfo(LibInfo& libInfo) const
    {
        (void)libInfo;

        return {};
    }

    /**
     * Opens a session between an application and a token in a particular slot.
     *
     * @param slotID slot identifier.
     * @param flags  indicates the type of session.
     * @return Error.
     */
    RetWithError<UniquePtr<SessionContext>> OpenSession(pkcs11::SlotID slotID, uint32_t flags)
    {
        (void)slotID;
        (void)flags;

        return {nullptr, ErrorEnum::eNone};
    }

    /**
     * Destroys object instance.
     */
    ~LibraryContext() = default;
};

/**
 * A Curve represents a short-form Weierstrass curve.
 */
enum class EllipticCurve {
    /**
     * A Curve which implements NIST P-384 (FIPS 186-3, section D.2.4), also known as secp384r1
     **/
    eP384
};

/**
 * Crypto private key extended with object handles.
 */
class PrivateKey {
public:
    /**
     * Constructs object instance with not initialized key part.
     *
     * @param privHandle private key handle.
     * @param pubHandle public key handle.
     */
    PrivateKey(
        ObjectHandle privHandle = 0, ObjectHandle pubHandle = 0, SharedPtr<crypto::PrivateKeyItf> privKey = nullptr)
        : mPrivHandle(privHandle)
        , mPubHandle(pubHandle)
        , mPrivKey(privKey)
    {
    }

    /**
     * PKCS11 priv key handle.
     */
    ObjectHandle GetPrivHandle() const { return mPrivHandle; }

    /**
     * PKCS11 pub key handle.
     */
    ObjectHandle GetPubHandle() const { return mPubHandle; }

    /**
     * PKCS11 priv key handle.
     */
    SharedPtr<crypto::PrivateKeyItf> GetPrivKey() { return mPrivKey; }

private:
    ObjectHandle                     mPrivHandle, mPubHandle;
    SharedPtr<crypto::PrivateKeyItf> mPrivKey;
};

/**
 * A helper class for a base Cryptoki API.
 */
class Utils {
public:
    /**
     * Creates an object instance.
     *
     * @param session session context.
     * @param allocator allocator for token/session objects.
     */
    Utils(pkcs11::SessionContext& session, Allocator& allocator)
    {
        (void)session;
        (void)allocator;
    }

    /**
     * Creates an RSA key pair on the token.
     *
     * @param id key pair id.
     * @param label key pair label.
     * @param bitsCount key size.
     * @return RetWithError<PrivateKey>.
     */
    RetWithError<PrivateKey> GenerateRSAKeyPairWithLabel(
        const Array<uint8_t>& id, const String& label, size_t bitsCount)
    {
        (void)id;
        (void)label;
        (void)bitsCount;

        return {PrivateKey()};
    }

    /**
     * Creates a ECDSA key pair on the token using curve.
     *
     * @param id token id.
     * @param label label.
     * @param curve elliptic curve.
     * @return RetWithError<PrivateKey>.
     */
    RetWithError<PrivateKey> GenerateECDSAKeyPairWithLabel(
        const Array<uint8_t>& id, const String& label, EllipticCurve curve)
    {
        (void)id;
        (void)label;
        (void)curve;

        return {PrivateKey()};
    }

    /**
     * Retrieves a previously created asymmetric key pair.
     *
     * @param id key id.
     * @param label key label.
     * @return RetWithError<PrivateKey>.
     */
    RetWithError<PrivateKey> FindPrivateKey(const Array<uint8_t>& id, const String& label)
    {
        (void)id;
        (void)label;

        return {PrivateKey()};
    }

    /**
     * Deletes private key for the token.
     *
     * @param key private key to be deleted.
     * @return Error.
     */
    Error DeletePrivateKey(const PrivateKey& key)
    {
        (void)key;

        return {};
    }

    /**
     * Imports a certificate onto the token.
     *
     * @param id certificate id.
     * @param label certificate label.
     * @param cert certificate.
     * @return Error.
     */
    Error ImportCertificate(const Array<uint8_t>& id, const String& label, const crypto::x509::Certificate& cert)
    {
        (void)id;
        (void)label;
        (void)cert;

        return {};
    }

    /**
     * Checks whether certificate with specified attributes has been imported.
     *
     * @param issuer certificate issuer.
     * @param serialNumber certificate serialNumber.
     * @return Error.
     */
    RetWithError<bool> HasCertificate(const Array<uint8_t>& issuer, const Array<uint8_t>& serialNumber)
    {
        (void)issuer;
        (void)serialNumber;

        return {false};
    }

    /**
     * Deletes a previously imported certificate.
     *
     * @param id certificate id.
     * @param label certificate label.
     * @return Error.
     */
    Error DeleteCertificate(const Array<uint8_t>& id, const String& label)
    {
        (void)id;
        (void)label;

        return {};
    }

    /**
     * Converts PKCS11 UTF8 byte array to aos string.
     *
     * @param src source UTF8 byte array.
     * @param dst destination string.
     * @return Error.
     */
    static Error ConvertPKCS11String(const Array<uint8_t>& src, String& dst)
    {
        (void)src;
        (void)dst;

        return {};
    }
};

/**
 * Manages PKCS11 libraries.
 */
class PKCS11Manager {
public:
    /**
     * Opens PKCS11 library.
     *
     * @param library path to pkcs11 shared library.
     * @return SharedPtr<LibraryContext>
     */
    SharedPtr<LibraryContext> OpenLibrary(const String& library)
    {
        (void)library;

        return {};
    }
};

} // namespace pkcs11
} // namespace aos

#endif
