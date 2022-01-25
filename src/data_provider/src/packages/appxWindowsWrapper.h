/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * January 23, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <iostream>
#include "ipackageWrapper.h"
#include "registryHelper.h"
#include "stringHelper.h"
#include "sharedDefs.h"


constexpr auto FILE_ASSOCIATIONS_REGISTRY { "\\Capabilities\\FileAssociations" };
constexpr auto URL_ASSOCIATIONS_REGISTRY  { "\\Capabilities\\URLAssociations" };
constexpr auto OPTIONAL_NAME_REGISTRY     { "Local Settings\\MrtCache" };

class AppxWindowsWrapper final : public IPackageWrapper
{
    public:

        explicit AppxWindowsWrapper(const HKEY key, const std::string& subKey)
            : m_key{ key },
              m_subKey{ subKey },
              m_format{ "win" }
        {
            getInformationPackages();
        }

        ~AppxWindowsWrapper() = default;

        std::string name() const override
        {
            return m_name;
        }

        std::string version() const override
        {
            return m_version;
        }

        std::string groups() const override
        {
            return UNKNOWN_VALUE;
        }

        std::string description() const override
        {
            return UNKNOWN_VALUE;
        }

        std::string architecture() const override
        {
            return m_architecture;
        }

        std::string format() const override
        {
            return m_format;
        }

        std::string osPatch() const override
        {
            return UNKNOWN_VALUE;
        }

        std::string source() const override
        {
            return m_vendor;
        }

        std::string location() const override
        {
            return m_location;
        }

    private:
        HKEY m_key;
        std::string m_subKey;
        std::string m_format;
        std::string m_name;
        std::string m_version;
        std::string m_vendor;
        std::string m_architecture;
        std::string m_location;

        bool isAppxRegistry()
        {
            Utils::Registry registry(m_key, m_subKey, KEY_READ | KEY_ENUMERATE_SUB_KEYS);

            return registry.enumerate().size() != 0 ? true : false;
        }

        void getInformationPackages()
        {
            if (isAppxRegistry())
            {
                constexpr auto INDEX_FIRST_PART_NAME { 0 };
                const auto fullName { Utils::split(m_subKey, '\\').back() };
                const auto fields { Utils::split(fullName, '_') };
                constexpr auto INDEX_ARCHITECTURE { 2 };
                constexpr auto INDEX_VERSION { 1 };

                Utils::Registry packageReg(m_key, m_subKey);

                if (fields.size() >= 3)
                {
                    m_version = fields.at(INDEX_VERSION);
                    m_architecture = getArchitecture(fields.at(INDEX_ARCHITECTURE));
                    m_location = getLocation(packageReg);
                    m_name = getName(fields.at(INDEX_FIRST_PART_NAME), packageReg);
                    m_vendor = getVendor(packageReg);
                }
            }
        }

        const std::string getArchitecture(const std::string& field)
        {
            std::string architecture { UNKNOWN_VALUE };

            if (!field.compare("x64"))
            {
                architecture = "x86_64";
            }
            else if (!field.compare("x86"))
            {
                architecture = "i686";
            }

            return architecture;
        }

        const std::string getLocation(Utils::Registry& registry)
        {
            std::string location;

            return registry.string("PackageRootFolder", location) ? location : UNKNOWN_VALUE;
        }

        const std::string getName(const std::string& fullName, Utils::Registry& registry)
        {
            std::string name;
            const auto fields{ Utils::split(fullName, '.') }; // Only will use the last element of vector
            constexpr auto INVALID_NAME_APP { "@{" };

            for (const auto& folder : registry.enumerate())
            {
                try
                {
                    std::string value;
                    Utils::Registry capabilitiesReg(m_key, m_subKey + "\\" + folder + "\\Capabilities");

                    if (capabilitiesReg.string("ApplicationName", value))
                    {
                        name = value;
                    }
                }
                catch (...)
                {
                }
            }

            const auto pos { name.find(INVALID_NAME_APP) };

            // The name variable contain the key of another registry with the application name
            if (pos != std::string::npos && pos == 0)
            {
                try
                {
                    std::string registryName;
                    const std::string subkey { m_subKey.substr(0, m_subKey.find("Local Settings"))  };

                    for (const auto& folder : Utils::Registry(m_key, subkey + OPTIONAL_NAME_REGISTRY, KEY_READ | KEY_ENUMERATE_SUB_KEYS).enumerate())
                    {
                        if (folder.find(fields.back()) != std::string::npos)
                        {
                            registryName = folder;
                            break;
                        }
                    }

                    if (registryName.size() != 0 )
                    {
                        const std::string key {name};

                        name = searchKeyOnSubRegistries(subkey + OPTIONAL_NAME_REGISTRY + "\\" + registryName, key);
                    }
                }
                catch (...)
                {
                }
            }

            const auto index { name.find(INVALID_NAME_APP) };
            return (index != std::string::npos && index == 0) ? "" : name;
        }

        const std::string getVendor(Utils::Registry& registry)
        {
            std::string vendor;

            for (const auto& folder : registry.enumerate())
            {
                try
                {
                    Utils::Registry fileReg(m_key, m_subKey + "\\" + folder + FILE_ASSOCIATIONS_REGISTRY, KEY_READ | KEY_QUERY_VALUE);
                    vendor = searchPublisher(fileReg);

                    if (vendor.size() == 0)
                    {
                        Utils::Registry urlReg(m_key, m_subKey + "\\" + folder + URL_ASSOCIATIONS_REGISTRY, KEY_READ | KEY_QUERY_VALUE);
                        vendor = searchPublisher(urlReg);
                    }
                }
                catch (...)
                {
                }
            }

            return vendor;
        }

        const std::string searchKeyOnSubRegistries(const std::string& path, const std::string& key)
        {
            std::string value;
            Utils::Registry registry(m_key, path);

            if (!registry.string(key, value))
            {
                for (const auto& folder : Utils::Registry(m_key, path).enumerate())
                {
                    std::string tempPath { path + "\\" + folder };
                    value = searchKeyOnSubRegistries(tempPath, key);

                    if (value.size())
                    {
                        break;
                    }
                }
            }

            return value;
        }

        const std::string searchPublisher(Utils::Registry& registry)
        {
            std::string publisher;
            const std::string subkey { m_subKey.substr(0, m_subKey.find("Local Settings"))  };

            for (const auto& value : registry.enumerateValueKey())
            {
                std::string data;
                std::string folder;

                registry.string(value, folder);
                Utils::Registry pubRegistry(m_key, subkey + folder + "\\Application");

                if (pubRegistry.string("ApplicationCompany", data))
                {
                    const auto index { data.find("@{") };

                    if (index != 0)
                    {
                        publisher = data;
                        break;
                    }
                }
            }

            return publisher;
        }
};

