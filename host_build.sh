#!/bin/bash

set +x

PrintNextStep () {
  echo
  echo "====================================="
  echo "  $1"
  echo "====================================="
  echo
}


#==============================================
if [ "$1" == "clean" ]; then
  PrintNextStep "Clean artifacts"

  rm -rf ./build/
  conan remove 'mbedtls*' -c
  conan remove 'gtest*' -c
fi

#==============================================
PrintNextStep "Setting up conan default profile"

conan profile detect --force
if [ $? -ne 0 ]; then
  echo "!ERROR"; exit 1
fi

#==============================================
PrintNextStep "Setting up mbedtls package"

mbedtls_list=`conan list 'mbedtls*' 2>/dev/null`

if [[ $mbedtls_list != *mbedtls* ]]; then
  echo "MbedTLS doesn't exists. Building package..."
  conan create ./conan/conan-mbedtls.py --settings=build_type=Debug
else
  echo "MbedTLS already exists!"
fi

#==============================================
PrintNextStep "Generate conan toolchain"

conan install ./conan/ --output-folder build --settings=build_type=Debug --build=missing
if [ $? -ne 0 ]; then
  echo "!ERROR"; exit 1
fi


#==============================================
PrintNextStep "Run cmake"

cd ./build

cmake .. -DCMAKE_TOOLCHAIN_FILE=./conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_COVERAGE=ON -DWITH_TEST=ON
if [ $? -ne 0 ]; then
  echo "!ERROR"; exit 1
fi

#==============================================
PrintNextStep "Run make"

make -j4
if [ $? -ne 0 ]; then
  echo "!ERROR"; exit 1
fi

#==============================================
echo
echo "Build succeeded!"
