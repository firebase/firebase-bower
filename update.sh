#!/bin/bash
set -ev

curl -o releases.json https://www.gstatic.com/firebasejs/releases.json

VERSION=$(node -p "require('./releases.json').current.version")

echo $VERSION

get-from-gstatic() {
  local file_name="$1"; shift
  echo -e "\nDownloading $file_name ..."
  if ! curl -O -f "https://www.gstatic.com/firebasejs/$VERSION/$file_name"; then
      echo "!!!!! Error downloading v$VERSION of $file_name from gstatic!!!"
      exit 1
  fi
}

SERVICES="app auth database storage messaging firestore functions performance analytics remote-config app-check"
MAPS="app database storage messaging firestore functions performance analytics remote-config app-check"

for service in $SERVICES; do
  get-from-gstatic "firebase-$service.js"
done

for map in $MAPS; do
  get-from-gstatic "firebase-$map.js.map"
done

echo "|----- Bumping version number of bower.json to $VERSION... -----|"

echo "$(node -p "JSON.stringify(Object.assign(require('./bower.json'), { version: '$VERSION' }), null, 2)")" > bower.json

if [[ $? -ne 0 ]]; then
  echo "!!!!! Error: Failed to bump version number of bower.json to $VERSION. !!!!!"
  exit 1
fi

echo "|----- Pushing the updated code to the firebase/firebase-bower repository... -----|"

git add .

if [[ $? -ne 0 ]]; then
  echo "!!!!! Error: Failed to do 'git add' from within the firebase-bower directory. !!!!!"
  exit 1
fi

git commit -m "[firebase-release] Updated Firebase web client to $VERSION"

if [[ $? -ne 0 ]]; then
  echo "!!!!! Error: Failed to do 'git commit' from within the firebase-bower directory. !!!!!"
  exit 1
fi

git tag -a "v$VERSION" -m "[firebase-release] Updated Firebase web client to $VERSION"

if [[ $? -ne 0 ]]; then
  echo "!!!!! Error: Failed to create git tag from within the firebase-bower directory. !!!!!"
  exit 1
fi

git push origin master
git push origin "v$VERSION"