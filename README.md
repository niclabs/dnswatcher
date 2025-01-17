# DNS Diagnóstico

Software desarrollado para realizar diagnósticos DNS sobre dominios, evaluando sincronía de registros SOA, autoridad, recursividad deshabilitada, soporte TCP y delegación. Los resultados se presentan en consola y se almacenan en un archivo JSON.

---

## **Pre-instalación**

### **Requisitos**
1. **Go**:
   - Instale Go siguiendo las instrucciones en [https://golang.org/doc/install](https://golang.org/doc/install).
   - Configure las variables de entorno `$GOROOT` y `$GOPATH`.

2. **Dependencias de Go**:
   Inicialice un módulo de Go:
   ```bash
   go mod init dnswatcher
   ```

   Instale las siguientes librerías de Go:
   ```bash
   go get github.com/miekg/dns
   go get github.com/niclabs/Observatorio/dnsUtils
   go get golang.org/x/net/idna
   ```

---

## Instalación
Clone este repositorio:
```bash
git clone <https://github.com/niclabs/dnswatcher.git>
```

Entre al directorio:
```bash
cd <dnswatcher>
```

---

## Uso

Ejecute el programa proporcionando un dominio como argumento:
```bash
go run maindns.go <dominio> (xxxxx.cl)
```

### **Salida esperada**
1. El diagnóstico se imprimirá en consola.
2. Un archivo JSON con los resultados se guardará en la carpeta `JSONS` (se creará automáticamente si no existe).

---

## Acknowledgments:

Observatorio:
@maitegm
@madestro
