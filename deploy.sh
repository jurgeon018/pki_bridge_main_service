# os
# sudo apt install rabbitmq-server
# sudo apt install nginx
# sudo apt install uwsgi
# sudo apt install python3
# sudo apt install python3-dev
# sudo apt install python3-setuptools
# sudo apt install python3-pip




# project
cd ~/projects/pki_bridge_main_service
cp -r ./deploy_configs_example/ ./deploy_configs/
cp ./src/.env.example ./src/.env
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
python3 src/manage.py collectstatic --noinput
cp src/pki_bridge/data_migrations.py src/pki_bridge/migrations/data_migrations.py
python3 src/manage.py migrate



# webservers(nginx+uwsgi)
sudo rm /etc/nginx/sites-enabled/pki_bridge_main_service
sudo rm /etc/systemd/system/pki_bridge_main_service.service
sudo ln -s ~/projects/pki_bridge_main_service/deploy_configs/pki_bridge_main_service         /etc/nginx/sites-enabled/
sudo ln -s ~/projects/pki_bridge_main_service/deploy_configs/pki_bridge_main_service.service /etc/systemd/system/
sudo systemctl enable nginx
sudo systemctl start nginx
sudo systemctl restart nginx
# sudo systemctl status nginx
sudo systemctl enable pki_bridge_main_service
sudo systemctl start pki_bridge_main_service
sudo systemctl restart pki_bridge_main_service
# sudo systemctl status pki_bridge_main_service
sudo systemctl daemon-reload



# celery
sudo supervisorctl stop pki_bridge_main_servicebeat
sudo supervisorctl stop pki_bridge_main_serviceworker
sudo rm /etc/supervisor/conf.d/celery_pki_bridge_main_service_worker.conf
sudo rm /etc/supervisor/conf.d/celery_pki_bridge_main_service_beat.conf
sudo ln -s ~/projects/pki_bridge_main_service/deploy_configs/celery_pki_bridge_main_service_worker.conf /etc/supervisor/conf.d/
sudo ln -s ~/projects/pki_bridge_main_service/deploy_configs/celery_pki_bridge_main_service_beat.conf   /etc/supervisor/conf.d/
sudo mkdir -p /var/log/celery
sudo touch /var/log/celery/pki_bridge_main_service_worker.log
sudo touch /var/log/celery/pki_bridge_main_service_beat.log
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start pki_bridge_main_serviceworker
#sudo supervisorctl restart pki_bridge_main_serviceworker
#sudo supervisorctl status pki_bridge_main_serviceworker
sudo supervisorctl start pki_bridge_main_servicebeat
#sudo supervisorctl restart pki_bridge_main_servicebeat
#sudo supervisorctl status pki_bridge_main_servicebeat
sudo tail -f /var/log/celery/pki_bridge_main_service_worker.log
sudo tail -f /var/log/celery/pki_bridge_main_service_beat.log
