## CMakeLists which sets up the custom targets in this project

# Add Nuvoton CMake list files to CMake module search path
#
# Normally, this is added via add_subdirectory(mbed-os), but
# add_subdirectory(custom_targets) must place in front and may
# rely on these cmake list files beforehand.
list(APPEND CMAKE_MODULE_PATH
    ${MBED_SOURCE_DIR}/targets/TARGET_NUVOTON/scripts
)

# To create a custom target, you first need to figure out the CMake name of the target
# from its Mbed name.  This name is calculated as:
#
# 1. Convert target to lowercase
# 2. Replace all underscores (_) with hyphens (-)
# 3. add "mbed-" prefix.
#
# So, the target named 'NUMAKER_IOT_M467' will be called mbed-numaker-iot-m467 in CMake.
# The Mbed build system will look for a target of this name when configuring, so make sure to create it.

add_library(mbed-numaker-m483kg INTERFACE)
target_include_directories(mbed-numaker-m483kg
    INTERFACE
        TARGET_NUMAKER_M483KG
)
target_link_libraries(mbed-numaker-m483kg INTERFACE mbed-m480)

add_library(mbed-nu-iot-m2354 INTERFACE)
target_link_libraries(mbed-nu-iot-m2354
    INTERFACE
        mbed-m2354
        mbed-m2354-tfm
)
if("NU_IOT_M2354" IN_LIST MBED_TARGET_LABELS)
    add_subdirectory(TARGET_NU_IOT_M2354)
endif()
