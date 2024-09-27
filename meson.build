project('wicuvanity', 'cuda', version: '1.0', license: 'MIT')

executable(
    meson.project_name(),
    sources: 'main.cu',
    dependencies: [
        dependency('cxxopts'),
        dependency('CUDAToolkit')
    ],
    override_options: ['cuda_std=c++20'],
    install: true
)