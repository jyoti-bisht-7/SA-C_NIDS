import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './styles.css'

// Get the root element (make sure <div id="root"></div> exists in index.html)
const rootEl = document.getElementById('root')

// Create root and render the app
const root = createRoot(rootEl)

root.render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
)
