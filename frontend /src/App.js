import React, { useState, useEffect } from 'react';
import axios from 'axios';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [file, setFile] = useState(null);
  const [scheduleTime, setScheduleTime] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [progress, setProgress] = useState(0);

  const handleRegister = async () => {
    await axios.post('/register', { username, password });
    alert('User registered');
  };

  const handleLogin = async () => {
    const response = await axios.post('/login', { username, password });
    if (response.data.status === 'success') {
      setIsLoggedIn(true);
      alert('Logged in');
    }
  };

  const handleUploadContacts = async () => {
    const formData = new FormData();
    formData.append('file', file);
    await axios.post('/upload-contacts', formData);
    alert('Contacts uploaded');
  };

  const handleSendMessage = async () => {
    await axios.post('/send-message', { message, schedule_time: scheduleTime });
    alert('Message sent/scheduled');
  };

  useEffect(() => {
    const eventSource = new EventSource('/progress');
    eventSource.onmessage = (e) => setProgress(e.data);
    return () => eventSource.close();
  }, []);

  return (
    <div>
      <h1>Telegram Bulk Sender</h1>
      {!isLoggedIn ? (
        <div>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button onClick={handleRegister}>Register</button>
          <button onClick={handleLogin}>Login</button>
        </div>
      ) : (
        <div>
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Enter your message"
          />
          <input type="file" onChange={(e) => setFile(e.target.files[0])} />
          <input
            type="datetime-local"
            value={scheduleTime}
            onChange={(e) => setScheduleTime(e.target.value)}
          />
          <button onClick={handleUploadContacts}>Upload Contacts</button>
          <button onClick={handleSendMessage}>Send Message</button>
          <p>Progress: {progress}%</p>
        </div>
      )}
    </div>
  );
}

export default App;
