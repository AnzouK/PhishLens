# Política de privacidad de PhishLens

Última actualización: 16 de octubre de 2026.

PhishLens es una extensión de Chrome que comprueba si los correos son
phishing. Esta página explica qué datos trata, adónde van y qué se
conserva. Se aplica a la extensión y al servidor alojado, PhishLens
Cloud, en `phishlens.dev`.

## En resumen

- PhishLens lee un correo solo cuando usted lo pide (los botones
  **Analizar**), o automáticamente si activa **Analizar automáticamente
  los correos nuevos** en los ajustes (desactivado por defecto).
- El correo se envía al servidor elegido en los ajustes: su propio
  ordenador (Docker o Python local), su propio servidor o PhishLens
  Cloud. La extensión no envía nada a ningún otro sitio, salvo los avisos que decida enviar (ver abajo).
- El servidor analiza el correo y devuelve un veredicto. No guarda el
  contenido de los correos, los remitentes ni los asuntos.
- Su historial de análisis se queda en su navegador. Nunca se envía.
- No hay cuentas, analítica, publicidad ni venta de datos.
- Puede avisar de un veredicto incorrecto o compartir las estadísticas
  de sus valoraciones. Solo se envía lo que ve y confirma: el texto del
  correo sin nombres, direcciones, números ni rutas de enlaces, o
  estadísticas sin ningún contenido de correo.

## Qué lee la extensión

Cuando se ejecuta un análisis, la extensión lee de la página abierta de
Gmail u Outlook:

- el texto del mensaje, su asunto y la dirección del remitente;
- los destinos de los enlaces del mensaje;
- las pistas de autenticación que muestra Gmail (enviado por, firmado
  por);
- con **Leer los encabezados completos** activado (por defecto), el
  mensaje original tal como lo ofrece la página «Mostrar original» de
  Gmail: todos los encabezados y las partes de texto, sin los archivos
  adjuntos;
- en un análisis de adjunto, el archivo adjunto.

La ventana de la extensión también lee los archivos que suelte en ella
y el texto que pegue.

## Adónde van los datos

Todas las solicitudes de análisis van a un único servidor, elegido en
los ajustes de la extensión:

| Opción | Adónde va su correo |
| --- | --- |
| Servidor local | Su propio ordenador (`127.0.0.1:8000`). No sale nada, salvo las consultas de inteligencia de amenazas indicadas abajo. |
| URL personalizada | El servidor que introdujo. Se aplica la política de su propietario. |
| PhishLens Cloud | El servidor alojado que gestiona el autor de PhishLens, en Oracle Cloud. No se guarda nada (ver abajo). |

El servidor comprueba los enlaces encontrados en un correo en servicios
de inteligencia de amenazas. Para ello envía **solo las direcciones de
los enlaces** (nunca el texto del correo, el remitente ni el asunto):

- Google Safe Browsing (URL completas, cuando hay una clave de API
  configurada);
- URLhaus de abuse.ch (URL completas);
- Spamhaus DBL (nombres de dominio, por DNS);
- PhishTank (comparación con una lista descargada en el servidor; sin
  solicitud por correo).

## Los avisos que decide enviar

Debajo de cada veredicto, PhishLens muestra el idioma detectado y un
enlace **¿Veredicto incorrecto? Avísenos**; la vista Estadísticas tiene
el mismo enlace para los análisis marcados como **Incorrecto**, y un
botón **Compartir mis estadísticas**. No se envía nada hasta que pulsa
**Enviar** después de leer lo que se enviará.

| Aviso | Qué se envía | Qué no se envía nunca |
| --- | --- | --- |
| Veredicto incorrecto | El asunto, el texto y los dominios de los enlaces de ese correo tras la anonimización (nombres después de un saludo o un título, su propio nombre y dirección tal como aparecen en la página del correo, direcciones de correo, números de teléfono, números largos como cuentas, tarjetas y códigos, IBAN, @nombres de usuario, la ruta y los parámetros de cada enlace), el texto tal como lo editó, el veredicto, las puntuaciones, el modo de cálculo, el idioma detectado y su respuesta, la versión de la extensión y el idioma de la interfaz | La dirección del remitente, el correo original, sus encabezados y sus adjuntos |
| Estadísticas | Para cada análisis de su historial: el día, dónde se hizo (Gmail, Outlook, ventana de la extensión), el veredicto, las puntuaciones, si el remitente era de confianza, su valoración Correcto / Incorrecto, el idioma detectado y su respuesta | Asuntos, remitentes, textos, enlaces |

Los avisos van a PhishLens Cloud, sea cual sea el servidor que use para
los análisis. El servidor anonimiza el texto por segunda vez con las
mismas reglas, guarda el aviso sin su dirección IP ni otros datos de la
solicitud (el registro del servidor web descrito más abajo sigue
registrando la solicitud durante 30 días) y devuelve una referencia. Los
avisos solo sirven para medir y mejorar PhishLens (por ejemplo, para
entrenar el modelo de texto con correos legítimos que juzgó mal); nunca
se publican ni se comparten. Se conservan como máximo dos años. Para que
se borre un aviso, abra una incidencia en
https://github.com/AnzouK/PhishLens/issues con su referencia (la
referencia por sí sola no revela nada del aviso).

Para poder avisar desde la vista Estadísticas, el texto anonimizado de
sus últimos análisis de Gmail y Outlook se guarda en su navegador
durante 7 días (50 correos como máximo). Nunca sale del navegador, salvo
que avise de ese análisis.

## Qué se conserva y durante cuánto tiempo

| Datos | Dónde | Cuánto tiempo |
| --- | --- | --- |
| Historial de análisis (asunto, remitente, veredicto, puntuaciones, palabras principales de la explicación, idioma detectado y su respuesta) | Su navegador (`chrome.storage.local`) | Hasta que lo borre (Estadísticas, **Borrar**), como máximo los últimos 500 análisis |
| Caché de explicaciones | Su navegador | Hasta que se elimine la extensión |
| Texto anonimizado de los análisis recientes de Gmail y Outlook, para los avisos | Su navegador | 7 días, 50 correos como máximo; se borra con el historial |
| Avisos que envió (texto anonimizado o estadísticas, ver arriba) | PhishLens Cloud | Dos años como máximo; se borran a petición con la referencia |
| Resultados del análisis automático (identificador de conversación, veredicto, puntuación) | Su navegador | Los últimos 500 correos |
| Ajustes | Su navegador | Hasta que se cambien |
| Veredictos de enlaces (URL, veredicto, fuente) | Caché del servidor (SQLite) | 24 horas |
| Resultados devueltos (veredicto, puntuaciones, veredictos de enlaces, palabras de la explicación), indexados por una huella del correo; no el correo en sí | Memoria del servidor | 24 horas, o hasta que el servidor se reinicie |
| Texto, encabezados y adjuntos de los correos | Memoria del servidor, durante la solicitud | No se guardan |
| Metadatos de las solicitudes (hora, ruta, estado, dirección IP, navegador) | Registros de la aplicación y del servidor web de PhishLens Cloud | 30 días; el contenido de las solicitudes nunca se registra |

PhishLens Cloud también cuenta los veredictos por modo de cálculo, para
supervisión (contadores de Prometheus). Son solo números, sin datos de
correos.

## Este sitio

`phishlens.dev` no instala cookies ni usa scripts de seguimiento,
así que no hay nada que aceptar. El número de visitas procede de los
registros del propio servidor web (página, hora, página de origen, tipo
de navegador, dirección IP), leídos con una herramienta alojada por el
propio sitio; se conservan 30 días y nunca se comparten. La página pide
a la API pública de GitHub el número de la última versión, que GitHub ve
como una solicitud normal de su navegador.

## Permisos

| Permiso | Por qué |
| --- | --- |
| `storage` | Guardar sus ajustes, el historial de análisis y las cachés en el navegador. |
| `notifications` | Avisarle cuando el análisis automático encuentra un correo de phishing. |
| `scripting` | Tras una actualización, poner la nueva versión de los botones de análisis en las pestañas de Gmail y Outlook ya abiertas, para que no tenga que recargarlas. |
| Acceso a `mail.google.com` | Añadir los botones de análisis y los avisos a Gmail y leer el correo que analiza. |
| Acceso a Outlook en la web (`outlook.office.com`, `outlook.office365.com`, `outlook.live.com`) | Lo mismo, en Outlook (solo análisis manuales). |
| Acceso a `127.0.0.1:8000`, `localhost:8000`, `phishlens.dev` | Enviar los análisis al servidor que eligió. |

## Sus opciones

- Desactive **Leer los encabezados completos** o **Analizar
  automáticamente los correos nuevos** en los ajustes cuando quiera.
- Use el servidor local para que los correos nunca salgan de su
  ordenador.
- Borre el historial desde la vista Estadísticas, o elimine la extensión
  para borrar todo lo que guardó.
- Si nunca envía un aviso, nada sale de su navegador salvo los propios
  análisis, hacia el servidor que eligió.

## Menores

PhishLens no está dirigido a menores y no recoge a sabiendas datos sobre
ellos.

## Cambios y contacto

Los cambios de esta política figuran en el
[registro de cambios](CHANGELOG.md) del proyecto. Para cualquier
pregunta, abra una incidencia en
https://github.com/AnzouK/PhishLens/issues, o informe de un problema de
seguridad de forma confidencial como se describe en
[SECURITY.md](SECURITY.md).
