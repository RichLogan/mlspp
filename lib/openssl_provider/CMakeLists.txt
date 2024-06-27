set(CURRENT_LIB_NAME openssl_provider)
add_library(${CURRENT_LIB_NAME} src/openssl_provider.cpp)
target_link_libraries(${CURRENT_LIB_NAME} PRIVATE hpke)
target_include_directories(${CURRENT_LIB_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>
  PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)

###
### Install
###

install(TARGETS ${CURRENT_LIB_NAME} EXPORT mlspp-targets)
install(
  DIRECTORY
    include/
  DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
)