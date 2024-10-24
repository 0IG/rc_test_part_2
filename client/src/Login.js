import React, { useState } from "react";
import axios from "axios";

const SignInForm = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const response = await axios.post("http://localhost:3001/login", {
        username,
        password,
      });
      setMessage(`Success! Jwt token => ${response.data.accessToken}`);

      console.log("Login successful: here's the jwt token ->", response.data);
    } catch (error) {
      setMessage("Login failed. Please check your credentials.");
      console.error("Error logging in:", error);
    }
  };

  return (
    <div>
      <h2>Sign In</h2>
      <form onSubmit={handleSubmit}>
        <div>
          There is no database and users:
          <br />
          Please enter following username and password to emulate
          your login experience
          <br />
          <br />
          username: admin
          <br />
          password: password
        </div>
        <br />
        <div>
          <label>Username:</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div>
          <label>Password:</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button type="submit">Sign In</button>
      </form>
      {message && <p>{message}</p>}
    </div>
  );
};

export default SignInForm;
