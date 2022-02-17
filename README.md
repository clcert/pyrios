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

## Instalación de Pyrios-UChile

### Requisitos




Verificación de Elección
---------------------

Para verificar una elección, primero, debes identificar la elección y 
descargar el archivo (_bundle filename_) de la elección en el siguiente link: 
https://participa.uchile.cl/elecciones

Luego de eso, debes correr el siguiente comando:

    helios_verify -bundle=<bundle_filename> -download=false -write=false -verify -logtostderr
