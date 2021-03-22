# os
sudo apt install rabbitmq-server
sudo apt install nginx
sudo apt install uwsgi
sudo apt install python3
sudo apt install python3-dev
sudo apt install python3-setuptools
sudo apt install python3-pip
# project 
cd ~
mkdir -p projects
cd projects
rm -rf pki_bridge
git clone https://git.fpprod.corp/menan/pki_bridge.git
cd pki_bridge
cp -r ./deploy_home/ ./deploy/
cp ./src/.env.example ./src/.env
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
python3 src/manage.py collectstatic --noinput
python3 src/manage.py migrate
# make prep_db
# webservers(nginx+uwsgi)
sudo rm /etc/nginx/sites-enabled/pki_bridge
sudo rm /etc/systemd/system/pki_bridge.service
sudo ln -s ~/projects/pki_bridge/deploy/pki_bridge         /etc/nginx/sites-enabled/
sudo ln -s ~/projects/pki_bridge/deploy/pki_bridge.service /etc/systemd/system/
sudo systemctl enable nginx
sudo systemctl start nginx
sudo systemctl restart nginx
# sudo systemctl status nginx
sudo systemctl enable pki_bridge
sudo systemctl start pki_bridge
sudo systemctl restart pki_bridge
# sudo systemctl status pki_bridge
sudo systemctl daemon-reload
# celery
sudo supervisorctl stop pki_bridgebeat
sudo supervisorctl stop pki_bridgeworker
sudo rm /etc/supervisor/conf.d/celery_pki_bridge_worker.conf
sudo rm /etc/supervisor/conf.d/celery_pki_bridge_beat.conf
sudo ln -s ~/projects/pki_bridge/deploy/celery_pki_bridge_worker.conf /etc/supervisor/conf.d/
sudo ln -s ~/projects/pki_bridge/deploy/celery_pki_bridge_beat.conf   /etc/supervisor/conf.d/
sudo mkdir -p /var/log/celery
sudo touch /var/log/celery/pki_bridge_worker.log
sudo touch /var/log/celery/pki_bridge_beat.log
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start pki_bridgeworker
#sudo supervisorctl restart pki_bridgeworker
#sudo supervisorctl status pki_bridgeworker
sudo supervisorctl start pki_bridgebeat
#sudo supervisorctl restart pki_bridgebeat
#sudo supervisorctl status pki_bridgebeat
