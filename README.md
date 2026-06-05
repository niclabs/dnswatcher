# Observatorio
Software desarrollado con el fin de recolectar y analizar datos DNS de un conjunto de dominios.

## Requisitos Generales
#### Geolite
Para poder geolocalizar las direcciones IP es necesario obtener una llave para usar los servicios de geolite, Maxmind. puedes registrarte [aquí](https://www.maxmind.com/en/geolite2/signup).
Esta llave debe ser guardada en el archivo de configuración config.yml con el nombre *geoiplicensekey*.

#### Postgresql
- Para poder utilizas el Observatorio, es necesario tener una base de datos potgreSQL
(si se va a correr en docker, aseguarse de darle acceso al container, modificando el archivo "pg_hba.conf" de postgres según corresponda y reiniciando el servicio)
- Configurar postgresql en Windows seguir las instrucciones [acá](https://www.postgresql.org/download/windows/). Asegúrese de crear el usuario postgres con su contraseña. Para crear la base de datos a utilizar siga los siguentes pasos:
    
        $ psql -U postgres
    
        postgres=# CREATE ROLE su_usuario LOGIN password 'su_contraseña'; //crear un usuario
    
        postgres=# CREATE DATABASE su_base_de_datos OWNER su_usuario; //crear una base de datos y asignarla al usuario creado
    
        postgres=# \q
    
        $
- Configurar postgresql en ubuntu

        $ sudo apt-get install postgresql
    
        $ sudo -u postgres psql postgres
            
        postgres=# CREATE ROLE su_usuario LOGIN password 'su_contraseña'; //crear un usuario
            
        postgres=# CREATE DATABASE su_base_de_datos OWNER su_usuario; //crear una base de datos y asignarla al usuario creado
            
        postgres=# \q
    
        $

#Archivo de configuración
 Independientemente de si usará Docker o no, es necesario llenar el archivo de configuración *config.yml* con los datos correspondientes
como se muestra a continuación:

        #Reminder: use spaces, yaml doesn't allow tabs
        #Geoip data
        geoip:
            geoippath: Geolite                              //folder where the geolite dabases are saved
            geoipasnfilename: GeoLite2-ASN.mmdb             //name of the asn geolite database
            geoipcountryfilename: GeoLite2-Country.mmdb     //name of the country geolite database
            geoiplicensekey: yourLicenseKey                 //geolite license key
        # Database configurations
        database:
            dbname: dbname                                  //name of the database you created
            dbuser: dbuser                                  //user you created
            dbpass: password                                //password for the user you created
            dbhost: localhost                               //postgresql host
            dbport: 5432                                    //postgresql port
        #runing arguments
        runargs:
            inputfilepath: input-example.txt                //file with the list of domains you want to test
            dontprobefilepath: dontprobefile.txt            //file with the list of IPs you dont want to query
            verbose: true                                   //print domains with collect in progress   
            concurrency: 100                                //desired concurrency
            ccmax: 100                                      //max concurrency
            maxretry: 2                                     //max attemps to retry a dns request
            debug: false                                    //print errors if true
            dnsservers: ["8.8.8.8", "1.1.1.1"]              //here put the dns servers you want to resolve the requests
        #End of config data
Puede duplicar el archivo config.yml.default y renombrar a config.yml, y modificar este. este archivo no debe ser agregado al repo, y se debe mantener en el archivo .gitignore, ya que contiene datos sensibles y credenciales.

Para poder ejecutar existen 2 opciones, ejecutarlo utilizando un contenedor Docker (lo que crea un ambiente aislado y evita instalar librerías adicionales), o ejecutarlo sin el contenedor, con la necesidad de inestalar todo manualmente.

## Ejecución sin contenedor Docker

#### Go lang
- Para descargar e instalar go lang siga las instrucciones que se encuentran [aquí](https://golang.org/doc/install).
Asegúrese de agregar las variables de entorno $GOROOT y $GOPATH

##Instalación

- Clonar el repositorio u obtener librería usando:

           $ go get github.com/niclabs/Observatorio

#### Instalar Librerías y dependencias

1. Librería DNS

        $ go get github.com/miekg/dns

        $ go build github.com/miekg/dns

2. Librería geoip2

        $ sudo apt install libgeoip1 libgeoip-dev geoip-bin (en caso de usar ubuntu)

        $ go get github.com/oschwald/geoip2-golang

3. Librería postgresql

        $ go get github.com/lib/pq

4. Librería para leer archivo de configuracion yml 

        $ go get gopkg.in/yaml.v2

- Para comenzar la recoleccion de datos ejecutar el siguiente comando:

        $go run $GOPATH/src/github.com/niclabs/Observatorio/main/main.go

Esta operación puede tardar de algunos minutos a varias horas dependiendo del tamaño de la lista de dominios que se quieren analizar y de las capacidades de la máquina que se esté utilizando.




## Utilizando Docker:

        
 - Clonar el repositorio desde github:
 
        git clone github.com/niclabs/Observatorio
        
 - Construir el contenedor:
 
        docker build -t observatorio .  
        
 - Finalmente, para ejecutar el programa, debe correr el contendor con el siguiente comando:
      
        docker run observatorio
        
 Esta operación puede tardar de algunos minutos a varias horas dependiendo del tamaño de la lista de dominios que se quieren analizar y de las capacidades de la máquina que se esté utilizando.
        

Una vez la ejecución haya terminado, se generarán una serie de archivos en formato *csv* y *json*, en la carpeta *csvs*, los cuales puede ver en una página web utilizando el código que se encuentra en https://github.com/niclabs/ObservatorioLAC-Graficos.git, o puede generar su propio set de datos desde la base de datos (un diagrama de la base de datos se puede ver [aquí](https://github.com/niclabs/Observatorio/wiki/database)). 

para obtener los archivos de la carpeta csvs ejecutar el siguiente comando:

        docker cp <containerID>:/Observatorio/csvs/ </local/dest/folder>

reemplazando el id del container y la carpeta de destino que desea utilizar



## Nuevos features

Se busca implementar nuevas métricas alineadas al estándar [RSSAC047](https://www.icann.org/groups/ssac/rssac-047). Para cada dominio de entrada, realiza consultas DNS reales y evalúa las respuestas según los siguientes criterios:

### Implementado

- [x] **Disponibilidad por versión de IP (IPv4/IPv6)** — Evalúa si los NS responden correctamente por ambas versiones del protocolo. *(RSSAC047 §5.1)*
- [x] **Disponibilidad por tipo de transporte (UDP/TCP)** — Verifica que los NS soporten consultas por UDP y TCP. *(RSSAC047 §5.1)*
- [x] **Latencia de respuesta** — Mide el tiempo de respuesta a una consulta SOA y lo compara contra los umbrales del estándar (250 ms UDP / 500 ms TCP). *(RSSAC047 §5.2)*
- [x] **Cumplimiento de estándares DNS y DNSSEC** — Valida respuestas sobre registros clave (SOA, NS, DNSKEY) y negativos (NXDOMAIN), verificando flags y registros de seguridad (RRSIG, NSEC/NSEC3). *(RSSAC047 §5.3)*
- [x] **Tasa de éxito/fallo en DNSSEC** — Calcula el porcentaje de respuestas DNSSEC correctamente validadas versus fallidas. *(RSSAC047 §5.3)*
- [x] **Validación de firma y registros DS** — Verifica que el registro DS corresponda con el DNSKEY publicado, comprobando la cadena de confianza. *(RSSAC047 §5.3)*
- [x] **Redundancia y distribución de servidores NS** — Cuenta cuántas subredes distintas cubren los NS del dominio. *(RSSAC047 §4.6)*
- [x] **Clasificación automática de errores DNSSEC** — Identifica y agrupa las causas frecuentes de fallo (ausencia de DS, DNSKEY, dominios sin firma). *(RSSAC047 §4.8)*

### Trabajo a futuro

- [ ] **Latencia de publicación** — Medir cuánto tarda un vantage point en observar un nuevo serial SOA tras un cambio en la zona. *(RSSAC047 §5.4)*
- [ ] **Detalles de fallos DNSSEC** — Desglose fino de errores: firmas inválidas, inconsistencias entre secciones, etc. *(RSSAC047 §4.8)*
- [ ] **Métricas bajo condiciones adversas** — Evaluar comportamiento ante latencia elevada, pérdida de paquetes o tráfico intenso.
- [ ] **Métricas agregadas a nivel de sistema (RSS)** — Disponibilidad y latencia a nivel de todo el sistema raíz. *(RSSAC047 §6)*
- [ ] **Separación entre respuestas positivas y negativas** — Aplicar reglas de validación distintas según el tipo de respuesta esperada. *(RSSAC047 §5.3)*
- [ ] **Inclusión de NSID en las consultas** — Identificar exactamente qué instancia respondió, útil para diagnóstico en redes anycast. *(RSSAC047 §4.8)*
- [ ] **Diversidad geográfica de vantage points** — Expandir a múltiples puntos de medición distribuidos por región y red (mínimo 20 recomendados). *(RSSAC047 §3.1, §3.2)*

Para más detalle ver la sección de Implementaciones/lista_implementaciones.txt



