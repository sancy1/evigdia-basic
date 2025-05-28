
# #!/bin/bash
# set -o errexit

# # Explicitly set Python path
# export PYTHONPATH="${PYTHONPATH}:/opt/render/project/src"

# pip install -r requirements.txt
# python manage.py collectstatic --noinput
# python manage.py migrate


#!/bin/bash
set -o errexit

# Set Python path
export PYTHONPATH="/opt/render/project/src:$PYTHONPATH"

# Install dependencies including Gunicorn
pip install --upgrade pip
pip install gunicorn  # Add this line
pip install -r requirements.txt

# Django setup
python manage.py collectstatic --noinput
python manage.py migrate