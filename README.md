# Search-Log-Information
## Propósito general
El propósito general del programa es entender que se lee de un log con una estructura libre.
El programa inicialmente parte de una estructura con un formato 

	** _TIMESTAMP_ <separador>campo1<separador>campo2<separador>...campon **

La evolución de script a, espero, programa sigue los siguientes pasos:

- Inicialmente se necesitaba poder leer y diferenciar líneas y multilíneas
  - s para líneas normales -f **nombre de fichero**
  - m para multilínea  -f **nombre de fichero**
