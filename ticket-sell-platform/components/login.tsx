import { useState } from "react";
import api from '../axiosConfig'; // Your configured axios instance
import cookie from 'js-cookie';


export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    try {
      console.log('Attempting Login:', { username });

      const response = await api.post('/api/login', { 
        username, 
        password 
      });

      cookie.set('token' , response.data.token)
      console.log("Login successful", response.data.name);
    } catch (err: any) {
      console.error('Login Error:', err);

      if (err.response) {
        setError(err.response.data.error || "Login failed");
      } else if (err.request) {
        setError("No response from server. Check network connection.");
      } else {
        setError("Unable to process login. Please try again.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="login-container border-2 rounded-lg p-5 shadow-lg bg-white">
      <h2 className="text-2xl font-bold mb-4">User Login</h2>
      <form onSubmit={handleLogin} className="space-y-4">
        <div className="form-group">
          <label htmlFor="username" className="block text-sm font-medium text-gray-700">Username</label>
          <input
            type="text"
            id="username"
            className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="password" className="block text-sm font-medium text-gray-700">Password</label>
          <input
            type="password"
            id="password"
            className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        {error && <p className="text-red-500 text-sm">{error}</p>}
        <button type="submit" className="w-full bg-blue-500 text-white py-2 rounded-md">Login</button>
      </form>
    </div>
  );
}