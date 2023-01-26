#!/bin/bash

sudo yum update -y
sudo yum install -y httpd
sudo systemctl enable httpd
sudo systemctl start httpd

sudo echo "<!DOCTYPE html>
<html>
<head>

<link
  rel="stylesheet"
  href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css"
/>

<style>
body {
  background-image: url("https://raw.githubusercontent.com/hansbreukelman/project_cloud/master/user_data/galaxy.jpeg");
  background-repeat: no-repeat;
  background-attachment: fixed;
  background-size: cover;
}

.image {
  display: block;
  margin-left: auto;
  margin-right: auto;
  margin-top: 7%;
  animation-delay: 3.5s;
  animation-duration: 2s; /* don't forget to set a duration! */
}

.left {
  width:100%;
  overflow:hidden;
}
.left {
  animation: left 3s;
}

@keyframes left {
  from {
    margin-left: 100%;
    width: 300%; 
  }

  to {
    margin-left: 0%;
    width: 100%;
  }
}

.right {
  width:100%;
  overflow:hidden;
}
.right {
  animation: 4s right;
}

@keyframes right {
  from {
    margin-right: 100%;
    width: 300%; 
  }

  to {
    margin-right: 0%;
    width: 100%;
  }
}

</style>

</head>

<body>

<h2 class="left" style="color:white;font-family:helvetica;text-align:center;">HELLO WORLD!</h2>

<h3 class="right" style="color:white;font-family:helvetica;text-align:center;">This is the user-data webpage!</h3>

<img class="animate__animated animate__jackInTheBox image" src="https://media.giphy.com/media/lnsTFyT6wUzItXsUV5/giphy.gif" width="30%" height="30%">


</body>
</html>" > /var/www/html/index.html