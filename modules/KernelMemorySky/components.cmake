set(MODULE_NAME KernelMemorySky)
set(MODULE_SOURCES
    ${CMAKE_SOURCE_DIR}/modules/KernelMemorySky/module.c
)
set(MODULE_LDS
    ${CMAKE_SOURCE_DIR}/modules/KernelMemorySky/module.lds
)
set(MODULE_INFO
    "KPM_NAME(\"KernelMemorySky\")"
    "KPM_VERSION(\"1.0.0\")"
    "KPM_LICENSE(\"GPL\")"
    "KPM_AUTHOR(\"FantasySR\")"
    "KPM_DESCRIPTION(\"Kernel memory read/write\")"
)