 <?php

use AmoCRM\Models\TaskModel;
use AmoCRM\Filters\ContactsFilter;
use AmoCRM\Collections\TasksCollection;
use AmoCRM\Helpers\EntityTypesInterface;
use AmoCRM\Exceptions\AmoCRMApiException;
use League\OAuth2\Client\Token\AccessTokenInterface;
use AmoCRM\Client\AmoCRMApiClient;
use League\OAuth2\Client\Token\AccessToken;

include_once __DIR__ . '/bootstrap.php';

$clientId = $_ENV['CLIENT_ID'];
$clientSecret = $_ENV['CLIENT_SECRET'];
$redirectUri = $_ENV['CLIENT_REDIRECT_URI'];

$apiClient = new AmoCRMApiClient($clientId, $clientSecret, $redirectUri);

$accessToken = getToken();

$apiClient->setAccessToken($accessToken)
	->setAccountBaseDomain($accessToken->getValues()['baseDomain'])
	->onAccessTokenRefresh(
		function (AccessTokenInterface $accessToken, string $baseDomain) {
			saveToken(
				[
					'accessToken' => $accessToken->getToken(),
					'refreshToken' => $accessToken->getRefreshToken(),
					'expires' => $accessToken->getExpires(),
					'baseDomain' => $baseDomain,
				]
			);
		}
	);

$contactsService = $apiClient->contacts();
$contactsFilter = new ContactsFilter();
$contactsFilter->setLimit($_ENV['API_PER_PAGE_LIMIT']);

$tasksService = $apiClient->tasks();
$tasksCollection = new TasksCollection();

try {
	$contactsCollection = $contactsService->get($contactsFilter, ['leads']);
} catch (AmoCRMApiException $e) {
	echo $e->getMessage() . ' on line -> ' . __LINE__;
	die;
}

foreach ($contactsCollection as $contactObj) {
	if (!$contactObj->leads) {
		$task = new TaskModel();
		$task->setText('Контакт без сделок')
			->setCompleteTill(mktime(23, 59, 59, date("n"), date("j"), date("Y")))
			->setEntityType(EntityTypesInterface::CONTACTS)
			->setEntityId($contactObj->id);
		$tasksCollection->add($task);
	}
}

try {
	$tasksCollection = $tasksService->add($tasksCollection);
} catch (AmoCRMApiException $e) {
	echo $e->getMessage() . __LINE__;
	die;
}

echo 'Количество созданных задач: ' . $tasksCollection->count();


function saveToken($accessToken)
{
    if (
        isset($accessToken)
        && isset($accessToken['accessToken'])
        && isset($accessToken['refreshToken'])
        && isset($accessToken['expires'])
        && isset($accessToken['baseDomain'])
    ) {
        $data = [
            'accessToken' => $accessToken['accessToken'],
            'expires' => $accessToken['expires'],
            'refreshToken' => $accessToken['refreshToken'],
            'baseDomain' => $accessToken['baseDomain'],
        ];

        file_put_contents($_ENV['TOKEN_FILE'], json_encode($data));
    } else {
        exit('Invalid access token ' . var_export($accessToken, true));
    }
}

function getToken()
{
    if (
        isset($_ENV['ACCESS_TOKEN'])
        && isset($_ENV['REFRESH_TOKEN'])
        && isset($_ENV['EXPIRES'])
        && isset($_ENV['BASE_DOMAIN'])
    ) {
        return new AccessToken([
            'access_token' => $_ENV['ACCESS_TOKEN'],
            'refresh_token' => $_ENV['REFRESH_TOKEN'],
            'expires' => $_ENV['EXPIRES'],
            'baseDomain' => $_ENV['BASE_DOMAIN'],
        ]);
    } else {
        exit('Token is invalid ');
    }
}