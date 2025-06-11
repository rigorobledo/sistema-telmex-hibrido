# 🔀 Sistema Híbrido - Telmex

Sistema unificado con detección automática

## 🚀 Deploy en Railway

Este proyecto está configurado específicamente para **Sistema Híbrido**.

### Variables de Entorno Requeridas:
- `DATABASE_URL`: URL completa de PostgreSQL
- `PORT`: Puerto (Railway lo asigna automáticamente)

### Comando de Deploy:
```bash
git add .
git commit -m "Deploy Sistema Híbrido"
git push
```

### Características:
- 🔀 **Tipo:** Sistema Híbrido
- 🚂 **Optimizado para Railway**
- 🔒 **Sistema de autenticación integrado**
- 📊 **PostgreSQL como base de datos**

### Estructura del Proyecto:
```
hibrido/
├── app.py                              ← Punto de entrada
├── sistema_completo_normalizacion.py   ← Sistema principal
├── requirements.txt                    ← Dependencias
├── railway.json                        ← Configuración Railway
└── README.md                          ← Este archivo
```

### Para Desarrollo Local:
```bash
pip install -r requirements.txt
streamlit run app.py
```

### Soporte:
- 📧 Contacta al equipo de desarrollo para soporte
- 🔧 Logs disponibles en Railway Dashboard

### Características Específicas del Sistema Híbrido:
- 🔀 Detección automática de modo (síncrono/asíncrono)
- 🚀 Launcher unificado con 3 opciones
- 📊 Dashboard completo con todas las funcionalidades
- 🎯 Ideal para uso general y producción
