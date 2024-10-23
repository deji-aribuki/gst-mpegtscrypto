project('mpegtscrypto', 'c', version : '1.0')

cc = meson.get_compiler('c')

gst_dep = dependency('gstreamer-1.0')
gst_base_dep = dependency('gstreamer-base-1.0')
gst_pbutils_dep = dependency('gstreamer-pbutils-1.0')
openssl_dep = dependency('openssl', required : true)
dvbcsa_dep = cc.find_library('dvbcsa')

dvbcsa_cflags = []
if dvbcsa_dep.found()
  dvbcsa_cflags += ['-DHAVE_LIBDVBCSA']
endif

conf = configuration_data()
conf.set('VERSION', '"@0@"'.format(meson.project_version()))
conf.set('PACKAGE', '"mpegtscrypto"')
configure_file(output: 'config.h', configuration: conf)

add_project_arguments('-DHAVE_CONFIG_H', language: 'c')

plugin_sources = [
  'src/gstmpegtscrypto.c',
  'src/gstmpegtspacketizer.c',
  'src/gstmpegtscipher.c'
]

inc_dirs = include_directories('src')

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
