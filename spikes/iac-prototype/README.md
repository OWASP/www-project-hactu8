# IAC Prototype - Micro Frontend Architecture

This is a prototype implementing a Micro Frontend (MFE) architecture with a React host application that embeds independent Streamlit applications.

## Architecture Overview

- **iac-host**: React application serving as the MFE host (port 3000)
- **iac-mfe-primary**: Primary micro frontend module (port 3001)
- **iac-dashboard**: Streamlit application for dashboard visualization (port 8511)
- **iac-registry**: Streamlit application for enterprise registry (port 8512)
- **iac-console**: Streamlit application for console operations (port 8513)

## Prerequisites

### Required Software

- **Node.js**: v22.16.0 or higher
- **Python**: 3.13.0 or higher
- **npm**: Comes with Node.js

### Installation Tools

If you don't have the required versions installed:

#### Node.js
- Using [nvm](https://github.com/nvm-sh/nvm):

  ```bash
  nvm install 22.16.0
  nvm use 22.16.0
  ```

- Or download directly from [nodejs.org](https://nodejs.org/)

#### Python
- Using [pyenv](https://github.com/pyenv/pyenv):

  ```bash
  pyenv install 3.13.0
  pyenv local 3.13.0
  ```

- Or download directly from [python.org](https://www.python.org/)

## Getting Started from Scratch

### 1. Clone the Repository

```bash
git clone <repository-url>
cd iac-prototype
```

### 2. Set Up React Host Application

```bash
cd iac-host
npm install
cd ..
```

### 3. Set Up Primary MFE Module

```bash
cd iac-mfe-primary
npm install
npm run build
cd ..
```

### 4. Set Up Streamlit Applications

#### Dashboard

```bash
cd iac-dashboard
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
deactivate
cd ..
```

#### Registry

```bash
cd iac-registry
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
deactivate
cd ..
```

#### Console

```bash
cd iac-console
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
deactivate
cd ..
```

## Running the Application

You have two options to run the application:

### Option 1: Manual Start (All Components)

Open 5 separate terminal windows and run each component:

#### Terminal 1 - Dashboard

```bash
cd iac-dashboard
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
streamlit run app.py --server.port 8511 --server.headless false --browser.gatherUsageStats false
```

#### Terminal 2 - Registry

```bash
cd iac-registry
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
streamlit run app.py --server.port 8512 --server.headless false --browser.gatherUsageStats false
```

#### Terminal 3 - Console

```bash
cd iac-console
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
streamlit run app.py --server.port 8513 --server.headless false --browser.gatherUsageStats false
```

#### Terminal 4 - MFE Primary

```bash
cd iac-mfe-primary
npm run serve:dist
```

#### Terminal 5 - Host Application

```bash
cd iac-host
npm run dev
```

### Option 2: Using VSCode Launch Configuration

If you're using Visual Studio Code, you can use the preconfigured launch configuration:

1. Open the project in VSCode
2. Go to the Run and Debug panel (Ctrl+Shift+D / Cmd+Shift+D)
3. Select "Run all" from the dropdown
4. Click the green play button

This will start all components simultaneously.

## Accessing the Applications

Once all components are running, you can access them at:

- **Host Application**: <http://localhost:3000>
- **MFE Primary**: <http://localhost:3001>
- **Dashboard**: <http://localhost:8511>
- **Registry**: <http://localhost:8512>
- **Console**: <http://localhost:8513>

## Project Structure

```plaintext
iac-prototype/
├── iac-host/                 # React host application (Vite + React 19)
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
├── iac-mfe-primary/          # Primary micro frontend module
│   ├── src/
│   └── package.json
├── iac-dashboard/            # Streamlit dashboard app
│   ├── app.py
│   ├── requirements.txt
│   └── .venv/
├── iac-registry/             # Streamlit registry app
│   ├── app.py
│   ├── requirements.txt
│   └── .venv/
└── iac-console/              # Streamlit console app
    ├── app.py
    ├── requirements.txt
    └── .venv/
```

## Technology Stack

### Frontend (Host & MFE)
- React 19.1.0
- React Router DOM 7.7.1
- Vite 7.0.4
- TypeScript 5.8.3
- Module Federation (@originjs/vite-plugin-federation)

### Streamlit Applications
- Streamlit 1.28.0+
- Pandas 2.0.0+
- Numpy 1.24.0+
- Plotly 5.15.0+
- OpenAI (for iac-console)

## Development

### Hot Reload

- The React host application supports hot module replacement (HMR)
- Streamlit applications will automatically reload on file changes
- Changes to MFE modules require rebuilding and may need a browser refresh

### Building for Production

#### Host Application

```bash
cd iac-host
npm run build
```

#### MFE Primary

```bash
cd iac-mfe-primary
npm run build
```

## Troubleshooting

### Port Already in Use

If you get port conflicts, you can change the ports by setting environment variables:

For React applications:

```bash
export VITE_PORT=3000  # or your preferred port
```

For Streamlit applications, change the `--server.port` argument when running.

### Python Virtual Environment Issues

If you encounter issues with the virtual environment:

```bash
cd <streamlit-app-directory>
rm -rf .venv
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Node Modules Issues

If you encounter issues with node modules:

```bash
cd <react-app-directory>
rm -rf node_modules package-lock.json
npm install
```

### CORS Issues

The host application is configured to accept requests from the MFE modules. If you encounter CORS issues, check the environment variables in `.vscode/launch.json` or your terminal environment.

## Environment Variables

### React Host (iac-host)
- `VITE_PORT`: Port for the host application (default: 5173, configured: 3000)
- `VITE_CORS_ORIGIN`: CORS origin for MFE modules (default: <http://localhost:3001>)

### MFE Primary (iac-mfe-primary)
- `VITE_PORT`: Port for the MFE module (default: 5173, configured: 3001)
- `VITE_CORS_ORIGIN`: CORS origin for host (default: <http://localhost:3000>)

## Additional Notes

- The iac-console application requires an OpenAI API key configured in a `.env` file
- All Streamlit applications run independently and can be accessed directly or embedded in the host
- The MFE architecture allows for independent deployment and development of each module
- Module Federation is used to share React and React DOM between the host and MFE modules

## Contributing

When contributing to this prototype:

1. Ensure all components start successfully
2. Test the integration between host and Streamlit apps
3. Verify that all ports are properly configured
4. Update this README if you add new components or change configurations

## License

[Add your license information here]
