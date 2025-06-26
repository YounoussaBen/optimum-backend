1. Get access to a paid Azure subscription.
2. Install Azure CLI on your Mac and log in.
3. Set the paid subscription as the active subscription in Azure CLI.
4. Create a resource group for your project.
5. Create a static public IPv4 address.
6. Create a virtual network and subnet.
7. Create a network interface linked to the static IP and subnet.
8. Create a B1s Ubuntu VM using the network interface.
9. Open ports 22, 80, and 443 on the VM.
10. Assign a DNS label to the public IP (optional).
11. SSH into the VM from your terminal.
12. Install Docker and Docker Compose on the VM.
13. Clone your Django project repo inside the VM.
14. Create a `.env` file inside your project.
15. Create and configure `docker-compose.yml` for Django and PostgreSQL.
16. Configure Django for production use (allowed hosts, static files, secret key).
17. Create an Azure Blob Storage account and container.
18. Configure Django to use Azure Blob Storage for media files.
19. Create an Azure PostgreSQL Flexible Server instance (burstable tier).
20. Whitelist the VM IP in the PostgreSQL server firewall.
21. Connect Django to the Azure PostgreSQL server via environment variables.
22. Run `docker-compose build` and `docker-compose up -d` to start the app.
23. Create a domain or subdomain and point it to the static IP using Cloudflare DNS.
24. Install NGINX on the VM.
25. Configure NGINX as a reverse proxy to forward ports 80 and 443 to Django’s port.
26. Install Certbot on the VM.
27. Use Certbot to issue and install an SSL certificate for your domain.
28. Configure NGINX to use the SSL certificate.
29. Verify HTTPS access to your Django API via domain.
30. Create a GitHub Actions workflow for CI/CD deployment.
31. Add required secrets to your GitHub repo (SSH key, VM IP, username).
32. Configure GitHub Actions to pull code and restart the Docker app on push.
33. Test automatic deployments from GitHub to Azure VM.
