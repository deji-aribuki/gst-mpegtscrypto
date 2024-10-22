project('mpegtscrypto', 'c', version : '1.0',
  default_options : ['warning_level=2'])

cc = meson.get_compiler('c')

# GStreamer dependency
gst_dep = dependency('gstreamer-1.0')
gst_base_dep = dependency('gstreamer-base-1.0')
gst_pbutils_dep = dependency('gstreamer-pbutils-1.0')

# OpenSSL dependency
openssl_dep = dependency('openssl', required : true)

# dvbcsa dependency
dvbcsa_dep = dependency('dvbcsa', required : false)
dvbcsa_dep = dependency('dvbcsa', required : false)
if not dvbcsa_dep.found()
  dvbcsa_dep = cc.find_library('dvbcsa')
endif
dvbcsa_cflags = []
if dvbcsa_dep.found()
  dvbcsa_cflags += ['-DHAVE_LIBDVBCSA']
endif

# This will make the VERSION macro available
conf = configuration_data()
conf.set('VERSION', '"@0@"'.format(meson.project_version()))
conf.set('PACKAGE', '"mpegtscrypto"')

# Generate a config.h file that contains the version macro
configure_file(output: 'config.h', configuration: conf)

# Source files
plugin_sources = [
  'src/gstmpegtscrypto.c',
  'src/gstmpegtspacketizer.c',
  'src/gstmpegtscipher.c'
]

# Include the src directory for headers
inc_dirs = include_directories('src')

add_project_arguments('-DHAVE_CONFIG_H', language: 'c')

# Build the plugin
gst_plugin = shared_library('gstmpegtscrypto',
  plugin_sources,
  include_directories: inc_dirs,
  install : true,
  c_args : dvbcsa_cflags,
  dependencies : [
    gst_dep,
    gst_base_dep,
    gst_pbutils_dep,
    openssl_dep,
    dvbcsa_dep,
  ],
  install_dir : join_paths(get_option('libdir'), 'gstreamer-1.0')
)

# Install the plugin
#install_data('plugin_description.xml', install_dir : join_paths(get_option('datadir'), 'gstreamer-1.0'))
