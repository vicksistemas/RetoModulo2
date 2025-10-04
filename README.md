El archivo notebook se ejecuta pero el resultado ya no lo probe, por falta de tiempo.
Posteriormente probe la respuesta de Gemini, ya que era mas simple, menos archivos y menos logica, en principio funciono una gran parte, pero vi que marcaba error de conexion en la base.
1.- Revise la base de datos y se encontraba correcta
2.- Revise el backend pero no entiendo mucho de fastapi, posteriormente revise archivos del FE y del BE nuevamente, observando que la parte de la BD todo era simulación.
3.- Al notar que la BD es simulada, a pesar de que el contenedor se forma y funciona decidi quitar esta parte del codigo de fastapi y finalmente el contenedor del BE se ejecuto
4.- Volvi a probar el FE y seguia mandando errores, relice pruebas con postman hasta entender como esta funcionando el BE, realice correcciones al script para
que ejecutara correctamente los llamados a fastAPI y finalmente funciono.
5.- Entrego documentacion de pruebas con respuesta de Gemini en la carpeta pruebas, tambien se adjunta la estructura de archivos propuestos con gemini ya corregidos

Ejecución de los contenedores (desde la raiz de la carpeta Gemini):
docker-compose up --build -d

Usuario|password de pruebas para loguin correcto
admin|123

Para registrar usuario se puede utilizar cualquier dato, solo se simula el registro, el cual gemini no lo construyo completo, solo acepta usuario y password, 
pero faltan los datos con los que va a generar el dashboard, edad, genero y estado.
