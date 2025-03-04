import axios from 'axios';

// Create axios instance with comprehensive config
const api = axios.create({
  baseURL: 'http://localhost:5000',
  timeout: 10000, // 10 second timeout
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
});

// Add request interceptor for logging
api.interceptors.request.use(
  (config) => {
    console.log('Axios Request Config:', {
      url: config.url,
      method: config.method,
      data: config.data
    });
    return config;
  },
  (error) => {
    console.error('Axios Request Error:', error);
    return Promise.reject(error);
  }
);

// Add response interceptor for comprehensive error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('Comprehensive Axios Error:', {
      message: error.message,
      code: error.code,
      status: error.response?.status,
      data: error.response?.data
    });

    if (error.response) {
      // Server responded with an error status
      console.error('Error Response:', error.response.data);
    } else if (error.request) {
      // Request made but no response received
      console.error('No Response Received:', error.request);
    } else {
      // Something went wrong setting up the request
      console.error('Error Setup:', error.message);
    }

    return Promise.reject(error);
  }
);

export default api;