setenv CUDA_HOME /usr/local/cuda-13.0.0
setenv PATH ${CUDA_HOME}/bin:${PATH}
setenv LD_LIBRARY_PATH ${CUDA_HOME}/lib64:${LD_LIBRARY_PATH}
setenv PKG_CONFIG_PATH /opt/mellanox/doca/lib64/pkgconfig:/opt/mellanox/dpdk/lib64/pkgconfig
setenv GDRCOPY_PATH_L /opt/mellanox/gdrcopy/src/
