<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ellaisys\Cognito\Auth;

use Ellaisys\Cognito\Guards\CognitoTokenGuard;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Redirect;

use Ellaisys\Cognito\AwsCognitoClient;
use Ellaisys\Cognito\AwsCognitoUserPool;

use Exception;
use Illuminate\Validation\ValidationException;
use Ellaisys\Cognito\Exceptions\NoLocalUserException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;


trait AuthenticatesUsers
{

    /**
     * Pulls list of groups attached to a user in Cognito
     *
     * @param string $username
     * @return mixed
     * @throws BindingResolutionException
     */
    protected function getAdminListGroupsForUser(string $username): mixed
    {
        $groups = null;

        try {
            $result = App::make(AwsCognitoClient::class)->adminListGroupsForUser($username);
            if (!empty($result)) {
                $groups = $result['Groups'];

                if ((!empty($groups)) && is_array($groups)) {
                    foreach ($groups as $key => &$value) {
                        unset($value['UserPoolId']);
                        unset($value['RoleArn']);
                    } //Loop ends
                } //End if
            } //End if
        } catch(Exception $e) {
            Log::error('AuthenticatesUsers:getAdminListGroupsForUser:Exception');
        } //Try-catch ends

        return $groups;
    } //End if


    /**
     * Attempt to log the user into the application.
     *
     * @param Request|Collection $request
     * @param string $guard (optional)
     * @param string $paramUsername (optional)
     * @param string $paramPassword (optional)
     * @param bool $isJsonResponse (optional)
     *
     * @return mixed
     * @throws ValidationException
     */
    protected function attemptLogin(Request|Collection $request, string $guard='web', string $paramUsername='email', string $paramPassword='password', bool $isJsonResponse=false): mixed
    {
        try {
            $returnValue = null;

            //Convert request to collection
            if ($request instanceof Request) {
                $request = collect($request->all());
            } //End if

            //Get the password policy
//            $passwordPolicy = app()->make(AwsCognitoUserPool::class)->getPasswordPolicy(true);
            $passwordPolicy = App::make(AwsCognitoUserPool::class)->getPasswordPolicy(true);

            //Validate request
            $validator = Validator::make($request->only([$paramPassword])->toArray(), [
                $paramPassword => 'required|regex:'.$passwordPolicy['regex']
            ], [
                'regex' => 'Must contain at least ' . $passwordPolicy['message']
            ]);
            if ($validator->fails()) {
                Log::error($validator->errors());
                throw new ValidationException($validator);
            } //End if

            //Authenticate User
            $returnValue = Auth::guard($guard)->attempt($request->toArray(), false, $paramUsername, $paramPassword);
        } catch (NoLocalUserException | CognitoIdentityProviderException | Exception $e) {
            $exceptionClass = basename(str_replace('\\', DIRECTORY_SEPARATOR, get_class($e)));
            $exceptionCode = $e->getCode();
            $exceptionMessage = $e->getMessage().':(code:'.$exceptionCode.', line:'.$e->getLine().')';
            if ($e instanceof CognitoIdentityProviderException) {
                $exceptionCode = $e->getAwsErrorCode();
                $exceptionMessage = $e->getAwsErrorMessage().':'.$exceptionCode;
            } //End if
            Log::error('AuthenticatesUsers:attemptLogin:'.$exceptionClass.':'.$exceptionMessage);

            if ($e instanceof ValidationException) {
                throw $e;
            } //End if

            if ($e instanceof CognitoIdentityProviderException) {
                $this->sendFailedCognitoResponse($e, $isJsonResponse, $paramUsername);
            }

            $returnValue = $this->sendFailedLoginResponse($request, $e, $isJsonResponse, $paramUsername);
        } //Try-catch ends

        return $returnValue;
    } //Function ends


    /**
     * Attempt to log the user into the application.
     *
     * @param Collection $request
     * @param string $guard (optional)
     * @param bool $isJsonResponse (optional)
     * @param string $paramName
     * @return mixed
     * @throws ValidationException
     */
    protected function attemptLoginMFA(Collection $request, string $guard='web', bool $isJsonResponse=false, string $paramName='mfa_code'): mixed
    {
        try {
//            if ($request instanceof Request) {
                //Validate request
                $validator = Validator::make($request->all(), $this->rulesMFA());

                if ($validator->fails()) {
                    throw new ValidationException($validator);
                } //End if

                $request = collect($request->all());
//            } //End if

            //Generate challenge array
            $challenge = $request->only(['challenge_name', 'session', 'mfa_code'])->toArray();

            //Fetch user details
            switch ($guard) {
                case 'web': //Web
                    if (Session::has($challenge['session'])) {
                        //Get stored session
                        $sessionToken = Session::get($challenge['session']);
                        $username = $sessionToken['username'];
                        $challenge['username'] = $username;
                    } else{
                        throw new HttpException(400, 'ERROR_AWS_COGNITO_SESSION_MFA_CODE');
                    } //End if
                    break;

                case 'api': //API
                    $authGuard = Auth::guard($guard);
                    /** @var CognitoTokenGuard $authGuard */
                    $challengeData = $authGuard->getChallengeData($challenge['session']);
                    $username = $challengeData['username'];
                    $challenge['username'] = $username;
                    break;
                
                default:
                    break;
            } //End switch

            //Authenticate User
            $claim = Auth::guard($guard)->attemptMFA($challenge);
        } catch (NoLocalUserException $e) {
            Log::error('AuthenticatesUsers:attemptLoginMFA:NoLocalUserException');
            $paramUsername = null;
            return $this->sendFailedLoginResponse($request, $e, $isJsonResponse, $paramUsername);
        } catch (CognitoIdentityProviderException $e) {
            Log::error('AuthenticatesUsers:attemptLoginMFA:CognitoIdentityProviderException');
            return $this->sendFailedLoginResponse($request, $e, $isJsonResponse, $paramName);
        } catch (Exception $e) {
            Log::error('AuthenticatesUsers:attemptLoginMFA:Exception');
            Log::error($e);
            $paramName = 'mfa_code'; //Switch ends
//            switch ($e->getMessage()) {
//                case 'ERROR_AWS_COGNITO_MFA_CODE_NOT_PROPER':
//                    $paramName = 'mfa_code';
//                    break;
//
//                default:
//                    $paramName = 'mfa_code';
//                    break;
//            } //Switch ends
            return $this->sendFailedLoginResponse($request, $e, $isJsonResponse, $paramName);
        } //Try-catch ends

        return $claim;
    } //Function ends


    /**
     * Handle Failed Cognito Exception
     *
     * @param CognitoIdentityProviderException $exception
     * @throws ValidationException
     */
    private function sendFailedCognitoResponse(CognitoIdentityProviderException $exception, bool $isJsonResponse=false, string $paramName='email')
    {
        throw ValidationException::withMessages([
            $paramName => $exception->getAwsErrorMessage(),
        ]);
    } //Function ends


    /**
     * Handle Generic Exception
     *
     * @param Collection $request
     * @param null $exception
     * @param bool $isJsonResponse
     * @param string $paramName
     * @return RedirectResponse|JsonResponse
     * @throws ValidationException
     */
    private function sendFailedLoginResponse(Collection $request, $exception=null, bool $isJsonResponse=false, string $paramName='email'): RedirectResponse|JsonResponse
    {
        $errorCode = 400;
        $errorMessageCode = 'cognito.validation.auth.failed';
        $message = 'FailedLoginResponse';

        if (!empty($exception)) {
            if ($exception instanceof CognitoIdentityProviderException) {
                $errorMessageCode = $exception->getAwsErrorCode();
                $message = $exception->getAwsErrorMessage();
            } elseif ($exception instanceof ValidationException) {
                throw $exception;
            } else {
                $errorCode = $exception->getStatusCode();
                $message = $exception->getMessage();
            } //End if
        } //End if

        if ($isJsonResponse) {
            return Response::json([
                'error' => $errorMessageCode,
                'message' => $message
            ], $errorCode);
        } else {
            return Redirect::back()
                ->withErrors([
                    'error' => $errorMessageCode,
                    $paramName => $message,
                ]);
        } //End if
    } //Function ends


    /**
     * Get the MFA authentication validation rules.
     *
     * @return array
     */
    protected function rulesMFA(): array
    {
        return [
            'challenge_name'    => 'required',
            'session'           => 'required',
            'mfa_code'          => 'required|numeric|min:4',
        ];
    } //Function ends

} //Trait ends
