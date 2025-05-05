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



