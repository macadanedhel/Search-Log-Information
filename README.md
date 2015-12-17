# Search-Log-Information
## Propósito general
El propósito general del programa es entender que se lee de un log con una estructura libre.
El programa inicialmente parte de una estructura con un formato 

*__TIMESTAMP__ <separador>campo1<separador>campo2<separador>...campoN*

La evolución de script a, espero, programa sigue los siguientes pasos:

### Identificación de líneas simples y múltiples

- Inicialmente se necesitaba poder leer y diferenciar líneas y multilíneas
  - single, s para líneas normales -f *nombre de fichero*
  - multi, m para multilínea  -f *nombre de fichero*
- Posteriormente hacerlo fichero a fichero llevaba a la muerte
  - directory, d *nombre de directorio*

## Búsqueda de patrones

- Surgió la necesidad de encontrar patrones que ayudaran a encontrar determinados patrones
  - user, u busca un usuario siguiendo un patrón de matrícula genérico basado en letras y números
  - PAN, p Primary account number
  - email, e
  - ipv4, i
  - BAN, b Bank account number
  - threat, t todo junto
  - substr, r *cadena* para buscar cadenas específicas dentro de los logs

## Normalización del log

- datetype, dt -d *nombre de directorio* para poder crear un grafo con la información de los logs se necesita normalizar el formato de fecha. Los formatos contemplados son:

ID  | Formato de fecha 
------------- | ------------- 
1 | \\d\{4\}-\\d\{1,2\}-\\d\{1,2\}T\\d\{1,2\}:\\d\{1,2\}:\\d\{1,2\}\.\\d+Z
2 | \\d\{4\}-\\d\{1,2\}-\\d\{1,2\}T\\d\{1,2\}:\\d\{1,2\}:\\d\{1,2\}\.\\d+|-\\d\{1,2\}:\\d+
3 | \\d\{4\}-\\d\{1,2\}-\\d\{1,2\} \\d\{1,2\}:\\d\{1,2\}:\\d\{1,2\}\.\\d+
4 | \\d\{4\}-\\d\{1,2\}-\\d\{1,2\} \\d\{1,2\}-\\d\{1,2\}-\\d\{1,2\}
5 | \\d\{1,2\}/\\d\{1,2\}/\\d\{4\} \\d\{1,2\}:\\d\{1,2\}:\\d\{1,2\}\.\\d+
6 | \\d\{1,2\}/\\d\{1,2\}/\\d\{4\} \\d\{1,2\}:\\d\{1,2\}:\\d\{1,2\}
7 | Ene\|Feb\|Mar\|Abr\|May\|Jun\|Jul\|Ago\|Sep\|Oct\|Nov\|\dic \\d\{1,2\} \\d\{1,2\}:\\d\{1,2\}:\\d\{1,2\}
8 | \\d\{4\}-\\d\{1,2\}-\\d\{1,2\} \\d\{1,2\}:\\d\{1,2\}:\\d\{1,2\},\\d\{3\}
9 | \\d\{1,2\}/\\d\{1,2\}/\\d\{4\} \\d\{1,2\}:\\d\{1,2\}:\\d\{1,2\}\.\\d+

Esto devuelve un ID necesario para luego definir que se va a producir como resultado

- KnowMN,k *nombre de fichero* devuelve la longitud mínima de campos variables dentro de un log simple

## Creación de un grafo para jugar

# Creación

# Normalización

# Visualización



# Dependencias 

* os, sys, re, codecs, argparse, functools, unicodedata 
* [sqlite3](https://www.sqlite.org/)
* [graphviz](http://www.graphviz.org/) 
* [networkx](https://networkx.github.io/) Pero al final no se usa, se puede borrar.
* [matplotlib](http://matplotlib.org/).pyplot as plt Pero al final no se usa, se puede borrar
* [pygraphviz](https://pygraphviz.github.io/) Pero al final no se usa, se puede borrar


