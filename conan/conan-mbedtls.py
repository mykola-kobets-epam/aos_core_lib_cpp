import os
from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout
from conan.tools.files import patch
from conan.tools.scm import Git

class MbedTLS(ConanFile):
    name = "mbedtls"
    branch = "v3.5.0"
    version = "patched-v3.5.0"
    settings = "os", "compiler", "build_type", "arch"
    options = {}
    default_options = {}

    patch_file = f"{name}-{branch}.patch"
    exports_sources = patch_file

    def source(self):
        git = Git(self)
        clone_args = ['--depth', '1', '--branch', self.branch]
        git.clone("https://github.com/Mbed-TLS/mbedtls.git", args=clone_args)
        patch(self, patch_file=os.path.join(self.export_sources_folder, self.patch_file), base_path=self.name)

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        variables = {"ENABLE_TESTING" : "OFF", "ENABLE_PROGRAMS" : "OFF"}
        cmake.configure(variables=variables, build_script_folder=self.name)
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.builddirs = ["lib/cmake/MbedTLS/"]
        self.cpp_info.set_property("cmake_find_mode", "none")
