cmake_minimum_required(VERSION 3.21)
project(gwcert VERSION 1.0.4 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets LinguistTools)
find_package(OpenSSL REQUIRED)

set(SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/certmanager.cpp
    src/pkistore.cpp
    src/dialogs/cagenedialog.cpp
    src/dialogs/csrgenedialog.cpp
    src/dialogs/certsigndialog.cpp
    src/dialogs/certviewdialog.cpp
    src/dialogs/subjectwidget.cpp
    src/dialogs/chainbuilddialog.cpp
)

set(HEADERS
    src/mainwindow.h
    src/certmanager.h
    src/pkistore.h
    src/dialogs/cagenedialog.h
    src/dialogs/csrgenedialog.h
    src/dialogs/certsigndialog.h
    src/dialogs/certviewdialog.h
    src/dialogs/subjectwidget.h
    src/dialogs/chainbuilddialog.h
)

set(RESOURCES
    resources/resources.qrc
)

# ── Translations (i18n) ──
set(TS_FILES
    translations/gwcert_zh_CN.ts
)

qt6_add_translation(QM_FILES ${TS_FILES})

add_executable(gwcert ${SOURCES} ${HEADERS} ${RESOURCES} ${QM_FILES})

target_include_directories(gwcert PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dialogs
)

target_link_libraries(gwcert PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
)

install(TARGETS gwcert RUNTIME DESTINATION bin)

# Auto-install runtime DLL dependencies (cross-compilation aware)
set(_exe_path "$<TARGET_FILE:gwcert>")
set(_vcpkg_bin "${CMAKE_PREFIX_PATH}/bin")
set(_mingw_gcc_dir "/usr/lib/gcc/x86_64-w64-mingw32/13-win32")
set(_mingw_usr_dir "/usr/x86_64-w64-mingw32/lib")
set(_objdump "${CMAKE_OBJDUMP}")
if(MINGW)
    install(CODE "
      # Windows system DLLs to skip (case-insensitive matching)
      set(_system_dlls
        KERNEL32 USER32 GDI32 MSVCRT ADVAPI32 SHELL32 OLE32 OLEAUT32
        WS2_32 MSWSOCK NTDLL SECUR32 WINMM SETUPAPI CFGMGR32 IMM32
        VERSION SHLWAPI DWMAPI UXTHEME USERENV WTSAPI32 NETAPI32
        IPHLPAPI DNSAPI CRYPT32 BCRYPT WLDAP32 COMCTL32 COMDLG32
        DBGHELP PSAPI MPR RPCRT4 SECHOST WINSPOOL
        AUTHZ D3D11 D3D12 DWRITE DXGI D3D9 DXVA2 EVR MF MFPLAT
        OPENGL32 GLU32 XINPUT1_4 PROPSYS
      )

      set(_search_dirs
        \"${_vcpkg_bin}\"
        \"${_mingw_gcc_dir}\"
        \"${_mingw_usr_dir}\"
      )

      # Recursive function to resolve DLL dependencies via objdump
      function(resolve_deps binary resolved_var)
        set(_stack \"\${binary}\")
        set(_all_resolved \"\")
        set(_visited \"\")

        while(_stack)
          list(POP_FRONT _stack _current)

          # Get DLL imports
          execute_process(
            COMMAND \"${_objdump}\" -p \"\${_current}\"
            OUTPUT_VARIABLE _objdump_out
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE
          )
          string(REGEX MATCHALL \"DLL Name: [^ \\t\\r\\n]+\" _matches \"\${_objdump_out}\")

          foreach(_match IN LISTS _matches)
            string(REGEX REPLACE \"DLL Name: \" \"\" _dll \"\${_match}\")
            list(FIND _visited \"\${_dll}\" _idx)
            if(NOT _idx EQUAL -1)
              continue()
            endif()
            list(APPEND _visited \"\${_dll}\")

            string(REGEX REPLACE \"\\\\.dll\$\" \"\" _dll_base \"\${_dll}\")
            string(TOUPPER \"\${_dll_base}\" _dll_upper)
            list(FIND _system_dlls \"\${_dll_upper}\" _sys_idx)
            if(NOT _sys_idx EQUAL -1)
              continue()
            endif()

            string(REGEX MATCH \"^(api-ms-|ext-ms-)\" _api_match \"\${_dll}\")
            if(_api_match)
              continue()
            endif()

            set(_found \"\")
            foreach(_dir IN LISTS _search_dirs)
              if(EXISTS \"\${_dir}/\${_dll}\")
                set(_found \"\${_dir}/\${_dll}\")
                break()
              endif()
            endforeach()

            if(_found)
              list(APPEND _all_resolved \"\${_found}\")
              list(APPEND _stack \"\${_found}\")
            else()
              message(WARNING \"Unresolved runtime dependency: \${_dll}\")
            endif()
          endforeach()
        endwhile()

        list(REMOVE_DUPLICATES _all_resolved)
        set(\${resolved_var} \"\${_all_resolved}\" PARENT_SCOPE)
      endfunction()

      resolve_deps(\"${_exe_path}\" _all_deps)

      foreach(_dep IN LISTS _all_deps)
        file(INSTALL DESTINATION \"\${CMAKE_INSTALL_PREFIX}/bin\"
          TYPE SHARED_LIBRARY FILES \"\${_dep}\")
      endforeach()

      list(LENGTH _all_deps _dep_count)
      message(STATUS \"Installed \${_dep_count} runtime dependencies.\")
    ")
elseif(WIN32)
    qt_generate_deploy_app_script(
        TARGET gwcert
        OUTPUT_SCRIPT gwcert_deploy_script
        NO_UNSUPPORTED_PLATFORM_ERROR
    )
    install(SCRIPT ${gwcert_deploy_script})

    file(GLOB _openssl_runtime_dlls
        "${OPENSSL_ROOT_DIR}/bin/*.dll"
    )
    if(_openssl_runtime_dlls)
        file(TO_CMAKE_PATH "${_openssl_runtime_dlls}" _openssl_runtime_dlls)
        install(FILES ${_openssl_runtime_dlls} DESTINATION bin)
    endif()
endif()

# Install Qt platform plugins (required for Qt GUI apps on Windows)
if(MINGW)
    set(_qt_plugins_dir "${CMAKE_PREFIX_PATH}/Qt6/plugins")
    install(FILES "${_qt_plugins_dir}/platforms/qwindows.dll"
        DESTINATION bin/platforms OPTIONAL)
    install(FILES "${_qt_plugins_dir}/styles/qmodernwindowsstyle.dll"
        DESTINATION bin/styles OPTIONAL)
    install(DIRECTORY "${_qt_plugins_dir}/imageformats"
        DESTINATION bin OPTIONAL FILES_MATCHING PATTERN "*.dll")
    install(DIRECTORY "${_qt_plugins_dir}/tls"
        DESTINATION bin OPTIONAL FILES_MATCHING PATTERN "*.dll")
endif()

install(FILES ${QM_FILES} DESTINATION share/gwcert/translations)

# Install documentation
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/README.md DESTINATION share/doc/gwcert)

# Install desktop entry and icon
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/resources/gwcert.desktop
    DESTINATION share/applications OPTIONAL)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/resources/icons/app.svg
    DESTINATION share/icons/hicolor/scalable/apps
    RENAME gwcert.svg OPTIONAL)

# Copy .qm translation files alongside the executable (for development builds)
add_custom_command(TARGET gwcert POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:gwcert>/translations
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${QM_FILES} $<TARGET_FILE_DIR:gwcert>/translations/
    COMMENT "Copying translation files...")
