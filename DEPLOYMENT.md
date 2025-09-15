# 🚀 Deployment Guide - Phishing Detection App

> ⚠️ **SECURITY WARNING**: Replace `YOUR_GEMINI_API_KEY_HERE` with your actual API key. Never commit real API keys to GitHub!

## 🌐 Easy Web-Based Deployment (No CLI Required)

### Option 1: Railway (Recommended - Easiest)

1. **Go to:** https://railway.app
2. **Click "Start a New Project"**
3. **Sign up with GitHub** (create account if needed)
4. **Click "Deploy from GitHub repo"**
5. **Select your repository** (you'll need to push this code to GitHub first)
6. **Add Environment Variable:**
   - Name: `GEMINI_API_KEY`
   - Value: `YOUR_GEMINI_API_KEY_HERE`
7. **Click "Deploy"**

### Option 2: Render

1. **Go to:** https://render.com
2. **Sign up with GitHub**
3. **Click "New +" → "Web Service"**
4. **Connect your GitHub repository**
5. **Configure:**
   - Build Command: `npm install`
   - Start Command: `node server.js`
6. **Add Environment Variable:**
   - Key: `GEMINI_API_KEY`
   - Value: `YOUR_GEMINI_API_KEY_HERE`
7. **Click "Create Web Service"**

### Option 3: Vercel (Web Interface)

1. **Go to:** https://vercel.com
2. **Sign up with GitHub**
3. **Click "New Project"**
4. **Import your GitHub repository**
5. **Configure:**
   - Framework Preset: Other
   - Build Command: `npm install`
   - Output Directory: `.`
6. **Add Environment Variable:**
   - Name: `GEMINI_API_KEY`
   - Value: `YOUR_GEMINI_API_KEY_HERE`
7. **Click "Deploy"**

## 📋 Steps to Push to GitHub

1. **Create a new repository on GitHub:**
   - Go to https://github.com
   - Click "New repository"
   - Name it: `phishing-detection-app`
   - Make it public
   - Don't initialize with README

2. **Push your code:**
   ```bash
   git remote add origin https://github.com/YOUR_USERNAME/phishing-detection-app.git
   git branch -M main
   git push -u origin main
   ```

3. **Then follow one of the deployment options above**

## 🎯 Your App Will Be Live At:
- Railway: `https://your-app-name.railway.app`
- Render: `https://your-app-name.onrender.com`
- Vercel: `https://your-app-name.vercel.app`

## 🔧 Important Notes:
- Your API key is safely stored as an environment variable
- The `.env` file is ignored by git (it's in `.gitignore`)
- Your app will automatically redeploy when you push changes to GitHub

## 🎉 After Deployment:
Your phishing detection app will be live on the internet and accessible to anyone!
