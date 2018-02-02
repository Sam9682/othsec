pkgname="othsec"
pkgver=0.0.1
pkgrel=1
pkgdesc="A command-line tool for sharing Internet traffic over the web"
arch=('i686' 'x86_64')
url="https://github.com/Sam9682/othsec"
license=('ELITELCO')
makedepends=('gcc' 'cmake' 'json-c' 'libwebsockets' 'vim')
source=("git+https://github.com/Sam9682/${pkgname}")
md5sums=('SKIP')

build() {
 
  cmake \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_BUILD_TYPE=Release \
    ..

  make
}

package() {
  options=('staticlibs' 'strip')
  cd "${srcdir}/build-${CARCH}"
  make DESTDIR=${pkgdir} install
}