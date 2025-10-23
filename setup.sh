#!/bin/bash

# NetDog Setup Script
# This script helps set up and runthe NetDog environment
# REQUIRES ROOT/SUDO PRIVILEGES

set -e

# Set chown for all files to both the current user and root/sudo group
CURRENT_USER=$(whoami)
sudo chown -R $CURRENT_USER:$(id -gn $CURRENT_USER) .

# Check if running as root/sudo
if [ "$EUID" -ne 0 ]; then 
    echo "❌ This script must be run with sudo privileges"
    echo "Please run: sudo ./setup.sh"
    exit 1
fi

echo "🐕 NetDog Setup Script"
echo "====================="
echo ""
echo "⚠️  WARNING: This tool performs network scanning"
echo "⚠️  Only scan networks you own or have explicit permission to scan"
echo "⚠️  Unauthorized scanning may be illegal in your jurisdiction"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cp .env.example .env
    
    # Generate a random secret key
    SECRET_KEY=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    
    # Update .env file
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/your-secret-key-here-change-in-production/$SECRET_KEY/" .env
    else
        sed -i "s/your-secret-key-here-change-in-production/$SECRET_KEY/" .env
    fi
    
    echo "✅ .env file created with random secret key"
else
    echo "ℹ️  .env file already exists"
fi

echo ""
echo "🚀 Starting NetDog services..."
echo ""

# Build and start services
if command -v docker-compose &> /dev/null; then
    docker-compose up -d --build
else
    docker compose up -d --build
fi
# NPM install for frontend
echo "🚀 Starting frontend installation..."
cd frontend
npm install
cd ..
echo "✅ Frontend installation completed."
# Restart Docker services to ensure frontend changes take effect
if command -v docker-compose &> /dev/null; then
    docker-compose restart netdog-frontend
else
    docker compose restart netdog-frontend
fi

# Ensure all services are up
if command -v docker-compose &> /dev/null; then
    docker-compose ps
else
    docker compose ps
fi 

echo ""
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check if services are running
if docker ps | grep -q "netdog-backend"; then
    echo "✅ Backend service is running"
else
    echo "❌ Backend service failed to start"
    exit 1
fi

if docker ps | grep -q "netdog-frontend"; then
    echo "✅ Frontend service is running"
else
    echo "❌ Frontend service failed to start"
    exit 1
fi

if docker ps | grep -q "netdog-worker"; then
    echo "✅ Worker service is running"
else
    echo "❌ Worker service failed to start"
    exit 1
fi

# Let user create an admin account with desired username and password (can also be set up via API later)
if docker ps | grep -q "netdog-backend"; then
    echo "📝 Creating admin account..."
    read -p "Enter admin username: " ADMIN_USERNAME
    read -sp "Enter admin password: " ADMIN_PASSWORD
    echo ""
    # Create admin account in the database
    docker exec -it netdog-backend python manage.py createsuperuser --username $ADMIN_USERNAME --email admin@example.com --noinput
    echo "✅ Admin account created"
else
    echo "❌ Backend service is not running. Cannot create admin account."
    exit 1
fi

echo ""
echo "🎉 NetDog is now running!"
echo ""
echo "Access the application at:"
echo "  Frontend: http://localhost:5173"
echo "  API: http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
echo ""
echo "⚠️  IMPORTANT SECURITY REMINDERS:"
echo "  1. Register a user account before starting scans"
echo "  2. Only scan networks you own or have explicit authorization for"
echo "  3. Unauthorized network scanning may violate laws in your jurisdiction"
echo "  4. Always document scan authorization and keep audit logs"
echo ""
echo "To view logs:"
echo "  sudo docker compose logs -f"
echo ""
echo "To stop services:"
echo "  sudo docker compose down"
echo ""
