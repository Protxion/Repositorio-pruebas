
# Comandos de linux 
 - cd -> Es para pocisionarnos en una carpeta o salir de cualquiera de ellas
 - ls -> Es para mostrar los archivos o carpetas que hay dentro de un directorio/carpeta
 - rm -> Es para eliminar carpetas/archivos
 - bash -> Nos permite iniciar instancias o ejecutar scripts
 - clear -> Limpia la consola
 - mkdir -> Crea un nuevo directorio
 - wget -> nos permite descargar archivos
 - unzip -> nos permite descomprimir archivos .zip
 - -h -> nos muestra todos los comandos
## Pip 
 - nos permite instalar o desinstalar paquetes de python
 - -r -> nos permite intstalar requerimientos/dependencias
## Python
 - nos permite ejecutar el interprete de python
 - -h -> nos muestra todos los comandos
# Clase de teoria hacking etico dia 2 30/08/2024
## Teoria
En el curso vimos las diferentes metodologias que se van a tratar, 
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
## The harvester
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
 

 