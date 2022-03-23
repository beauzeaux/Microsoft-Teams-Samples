// The following are wrappers around Microsoft Teams libraries to make them play nicer
const teamsPromise = Promise.race([
  new Promise(resolve => microsoftTeams.initialize(() => resolve())),
  new Promise((resolve, reject) => setTimeout(() => reject('Failed to initialize connection with Microsoft Teams'), 250))]);

async function openAuthPopup(redirectUri) {
  var url = new URL(redirectUri);
  // Since the OAuth partner might not allow the embedded webview popup
  // https://docs.microsoft.com/en-us/microsoftteams/platform/tabs/how-to/authentication/auth-oauth-provider
  url.searchParams.set('oauthRedirectMethod', '{oauthRedirectMethod}');
  url.searchParams.set('authId', '{authId}');
  await new Promise((resolve, reject) => microsoftTeams.authentication.authenticate({
    url: url.toString(),
    isExternal: true,
    height: 500,
    width: 400,
    successCallback: resolve, // we don't really need any info from the auth dialog, just that it completed
    failureCallback: reject
  }));
}

async function getAccessToken() {
  await teamsPromise;
  const accessToken = await new Promise((resolve, reject) => {
    microsoftTeams.authentication.getAuthToken({
      failureCallback: reject,
      successCallback: resolve,
    });
  });
  return accessToken;
}

// The UI elements we use / modify as part of our tab
const logoutButton = document.getElementById('logout');
const loginButton = document.getElementById('login');
const content = document.getElementById('content')

async function onLogout() {
  const accessToken = await getAccessToken();

  // Issue the request to the backend to log out the user. 
  await fetch('/github/logout', {
    method: 'PUT',
    headers: new Headers({
      authorization: `Bearer ${accessToken}`
    })
  });

  // Update the UI to reflect that the user isn't logged in.
  logoutButton.disabled = true;
  loginButton.disabled = false;
  content.innerText = "Please log in to see starred repositories";
}

async function onLogin()
{
  const accessToken = await getAccessToken();

  let response = await fetch('/github/repositories', {
    method: 'GET',
    headers: new Headers({
      authorization: `Bearer ${accessToken}`
    })
  });

  if (response.status == 412) {
    var authResponse = await response.json();
    console.log("Need to do the partner auth", { authResponse });

    await openAuthPopup(authResponse.redirectUri);

    // once the partner auth has completed, the user is logged in, update the UI
    console.log("Finished partner auth, user is now logged in");
    

    // re-run the request now that we are authenticated
    response = await fetch('/github/repositories', {
      method: 'GET',
      headers: new Headers({
        authorization: `Bearer ${accessToken}`
      })
    });
  }
  // If we hit this point, the user is logged in successfully. 
  // update the UI accordingly 
  logoutButton.disabled = false;
  loginButton.disabled = true;

  // read the response content and populate the content
  var responseJson = await response.json();
  content.innerText = JSON.stringify(responseJson, null, 2);
}

async function main() {
  console.log("Partner auth sample started");
  logoutButton.addEventListener('click', onLogout);
  loginButton.addEventListener('click', onLogin);
  await onLogin();
}

main().catch(err => console.error(err));