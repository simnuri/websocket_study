cmake_minimum_required(VERSION 3.12)
include(pico_sdk_import.cmake)

set(projname "picow_access_point_background")

project(${projname} C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

#include(example_auto_set_url.cmake)

add_executable(${projname}
        startpage.c
        picow_access_point.c
        dhcpserver/dhcpserver.c
        dnsserver/dnsserver.c
        #main.c
        )

target_include_directories(${projname} PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        #${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts
        ${CMAKE_CURRENT_LIST_DIR}/dhcpserver
        ${CMAKE_CURRENT_LIST_DIR}/dnsserver
        )


target_link_libraries(${projname} #picow_access_point_background
	pico_cyw43_arch_lwip_threadsafe_background
	pico_stdlib
        pico_mbedtls
        hardware_rtc
	)

# enable usb output, disable uart output
pico_enable_stdio_usb(${projname} 1)
pico_enable_stdio_uart(${projname} 0)

pico_add_extra_outputs(${projname})

