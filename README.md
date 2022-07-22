Pyrios-UChile
======

Pyrios es una herramienta que ejecuta la verificación de elecciones 
realizadas en [Participa UChile](https://participa.uchile.cl).
Esta herramienta está basada en el proyecto 
[Pyrios](https://github.com/google/pyrios) que verifica cualquier elección 
realizada en el sistema de votación [Helios](https://vote.heliosvoting.org). 

Las elecciones en Participa UChile utilizan criptografía para proteger las 
papeletas secretas y permitir la verificación pública: cualquier persona 
puede comprobar que los resultados de una elección fueron calculados de 
manera correcta.

## Descargar compilado

Ir a "Releases" en la barra lateral y bajar la última versión ejecutable existente para tu arquitectura y sistema operativo.

## Cómo Compilar

Si lo deseas, puedes compilar el programa usando el código fuente del repositorio.

1. [Instalar Go](https://go.dev/doc/install)
1. instalar el comando `git`, o descargar y descomprimir el código fuente listado en "Releases" a mano.
    1. Si usas el comando `git`, clona el repositorio con `git clone https://github.com/clcert/pyrios`.
1. En la carpeta del código fuente, ejecutar `go build`

Verificación de Elección
---------------------

Para verificar una elección, primero, debes identificar la elección y 
descargar el archivo (_bundle filename_) de la elección en el siguiente link: 
https://participa.uchile.cl/elecciones

Luego de eso, debes correr el siguiente comando:

    pyrios -bundle=<bundle_filename> -download=false -write=false -verify
