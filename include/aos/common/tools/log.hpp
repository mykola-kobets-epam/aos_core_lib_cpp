/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_LOG_HPP_
#define AOS_LOG_HPP_

#include "aos/common/tools/config.hpp"
#include "aos/common/tools/enum.hpp"
#include "aos/common/tools/error.hpp"
#include "aos/common/tools/noncopyable.hpp"

/**
 * Helper macro to display debug log.
 */
#if AOS_CONFIG_LOG_LEVEL >= AOS_CONFIG_LOG_LEVEL_DEBUG
#define LOG_MODULE_DBG(module) aos::Log(module, aos::LogLevelEnum::eDebug)
#else
#define LOG_MODULE_DBG(module) true ? (void)0 : aos::LogVoid() & aos::Log(module, aos::LogLevelEnum::eDebug)
#endif

/**
 * Helper macro to display info log.
 */
#if AOS_CONFIG_LOG_LEVEL >= AOS_CONFIG_LOG_LEVEL_INFO
#define LOG_MODULE_INF(module) aos::Log(module, aos::LogLevelEnum::eInfo)
#else
#define LOG_MODULE_INF(module) true ? (void)0 : aos::LogVoid() & Log(module, aos::LogLevelEnum::eInfo)
#endif

/**
 * Helper macro to display warning log.
 */
#if AOS_CONFIG_LOG_LEVEL >= AOS_CONFIG_LOG_LEVEL_WARNING
#define LOG_MODULE_WRN(module) aos::Log(module, aos::LogLevelEnum::eWarning)
#else
#define LOG_MODULE_WRN(module) true ? (void)0 : aos::LogVoid() & Log(module, aos::LogLevelEnum::eWarning)
#endif

/**
 * Helper macro to display error log.
 */
#if AOS_CONFIG_LOG_LEVEL >= AOS_CONFIG_LOG_LEVEL_ERROR
#define LOG_MODULE_ERR(module) aos::Log(module, aos::LogLevelEnum::eError)
#else
#define LOG_MODULE_ERR(module) true ? (void)0 : aos::LogVoid() & Log(module, aos::LogLevelEnum::eError)
#endif

namespace aos {

/**
 * Log level types.
 */
class LogLevelType {
public:
    enum class Enum { eDebug, eInfo, eWarning, eError, eNumLevels };

    static const Array<const char* const> GetStrings()
    {
        static const char* const sLogLevelStrings[] = {"debug", "info", "warning", "error"};

        return Array<const char* const>(sLogLevelStrings, ArraySize(sLogLevelStrings));
    };
};

using LogLevelEnum = LogLevelType::Enum;
using LogLevel     = EnumStringer<LogLevelType>;

/**
 * Log module types.
 */
class LogModuleType {
public:
    enum class Enum {
        eDefault,
        eSMLauncher,
        eSMServiceManager,
        eIAMCertHandler,
        eIAMIdentHandler,
        eIAMPermHandler,
        eCommonMonitoring,
        eCommonPKCS11,
        eCommonCrypto,
        eProvisionManager,
        eNumModules,
    };

    static const Array<const char* const> GetStrings()
    {
        static const char* const sLogModuleTypeStrings[] = {"default", "launcher", "servicemanager", "certhandler",
            "identhandler", "permhandler", "resourcemonitor", "pkcs11", "crypto", "provisionmanager"};

        return Array<const char* const>(sLogModuleTypeStrings, ArraySize(sLogModuleTypeStrings));
    };
};

using LogModuleEnum = LogModuleType::Enum;
using LogModule     = EnumStringer<LogModuleType>;

/**
 * Log line callback. Should be set in application to display log using application logging mechanism.
 */
using LogCallback = void (*)(LogModule module, LogLevel level, const String& message);

/**
 * Implements log functionality.
 */
class Log : private NonCopyable {
public:
    /**
     * Max log line length.
     */
    static size_t constexpr cMaxLineLen = AOS_CONFIG_LOG_LINE_LEN;

    /**
     * Constructs a new Log object.
     *
     * @param module log module type.
     * @param level log level type.
     */
    Log(LogModule module, LogLevel level)
        : mModule(module)
        , mLevel(level)
        , mCurrentLen(0) {};

    /**
     * Destroys the Log object and calls log callback.
     */
    ~Log()
    {
        auto callback = GetCallback();

        if (callback != nullptr) {
            callback(mModule, mLevel, mLogLine);
        }
    }

    /**
     * Sets application log callback.
     *
     * @param callback
     */
    static void SetCallback(LogCallback callback) { GetCallback() = callback; }

    /**
     * Logs string.
     *
     * @param str string to log.
     * @return Log&
     */
    Log& operator<<(const String& str)
    {
        auto freeSize = mLogLine.MaxSize() - mLogLine.Size();

        if (str.Size() > freeSize) {
            [[maybe_unused]] auto err = mLogLine.Insert(mLogLine.end(), str.begin(), str.begin() + freeSize);
            assert(err.IsNone());

            AddPeriods();

            return *this;
        }

        mLogLine += str;

        return *this;
    };

    /**
     * Logs object that implements Stringer interface.
     *
     * @param stringer object to log.
     * @return Log&
     */
    Log& operator<<(const Stringer& stringer) { return *this << stringer.ToString(); };

    /**
     * Logs int.
     *
     * @param i integer to log.
     * @return Log&
     */
    Log& operator<<(int i)
    {
        StaticString<12> tmpStr;

        tmpStr.Convert(i);

        return *this << tmpStr;
    };

    Log& operator<<(const Error& err)
    {
        *this << err.Message();

        if (err.Errno() != 0) {
            *this << " [" << err.Errno() << "]";
        }

        if (err.FileName() != nullptr) {
            *this << " (" << err.FileName() << ":" << err.LineNumber() << ")";
        }

        return *this;
    }

private:
    static LogCallback& GetCallback()
    {
        static LogCallback sLogCallback;

        return sLogCallback;
    }

    void AddPeriods()
    {
        if (mLogLine.Size() > 3) {
            mLogLine.Resize(mLogLine.Size() - 3);
            mLogLine += "...";
        }
    }

    StaticString<cMaxLineLen> mLogLine;
    LogModule                 mModule;
    LogLevel                  mLevel;
    size_t                    mCurrentLen;
};

/**
 *
 */
class LogVoid {
public:
    void operator&(const Log&) { }
};

} // namespace aos

#endif
