add_library(libfontmanager SHARED
	"${SOURCE_DIR}/amanomiko_patch.cpp"
)

target_compile_definitions(libfontmanager PRIVATE 
	"_CRT_SECURE_NO_WARNINGS"
	"libfontmanager"
)

target_link_libraries(libfontmanager
	FontManager
)

if(${IS_MSVC_COMPILER})
	set_target_properties(libfontmanager PROPERTIES 
		LINK_FLAGS "${YY_THUNKS_ENTRY} ${DEFAULT_LINK_FLAGS}"
	)
endif()