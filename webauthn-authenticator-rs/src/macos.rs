use std::ffi::{c_int, c_void};

use crate::error::WebauthnCError;
use crate::{AuthenticatorBackend, Url};
use base64urlsafedata::Base64UrlSafeData;
use dispatch::Semaphore;
use icrate::objc2::declare::{Ivar, IvarDrop, IvarType};
use icrate::objc2::rc::{Owned, Ownership, Shared};
use icrate::objc2::runtime::{Class, Protocol};
use icrate::objc2::{declare_class, extern_protocol, msg_send, msg_send_id, Encode};
use icrate::objc2::{rc::Id, ClassType, ConformsTo, ProtocolType};
use icrate::AppKit::{
    NSApp, NSApplication, NSBackingStoreBuffered, NSColor, NSWindow, NSWindowStyleMaskClosable,
    NSWindowStyleMaskMiniaturizable, NSWindowStyleMaskResizable, NSWindowStyleMaskTitled,
};
use icrate::AuthenticationServices::{
    ASAuthorization, ASAuthorizationController, ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding, ASAuthorizationCredential,
    ASAuthorizationPublicKeyCredentialAssertion, ASAuthorizationPublicKeyCredentialParameters,
    ASAuthorizationPublicKeyCredentialRegistration,
    ASAuthorizationSecurityKeyPublicKeyCredentialProvider, ASCOSEAlgorithmIdentifierES256,
    ASPresentationAnchor, ASPublicKeyCredential,
};
use icrate::Foundation::{
    CGPoint, CGSize, NSArray, NSData, NSError, NSObject, NSRect, NSRunLoop, NSString,
};
use webauthn_rs_proto::{
    AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, PublicKeyCredential,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegisterPublicKeyCredential,
};

pub struct Macos {}

impl Default for Macos {
    fn default() -> Self {
        // trace!("starting runloop");
        // unsafe { NSRunLoop::currentRunLoop().run() };
        // trace!("started runloop");
        Self {}
    }
}

#[repr(transparent)]
pub struct GCDSemaphore(dispatch::ffi::dispatch_semaphore_t);

impl GCDSemaphore {
    pub fn new() -> Self {
        trace!("creating semaphore");
        let semaphore = unsafe { dispatch::ffi::dispatch_semaphore_create(0) };
        Self(semaphore)
    }

    pub fn wait(&self) {
        unsafe {
            dispatch::ffi::dispatch_semaphore_wait(self.0, dispatch::ffi::DISPATCH_TIME_FOREVER);
        }
    }

    pub fn signal(&self) {
        unsafe {
            dispatch::ffi::dispatch_semaphore_signal(self.0);
        }
    }
}

impl Drop for GCDSemaphore {
    fn drop(&mut self) {
        trace!("dropping semaphore");
        unsafe { dispatch::ffi::dispatch_release(self.0) }
    }
}

unsafe impl Encode for GCDSemaphore {
    const ENCODING: icrate::objc2::Encoding = <*mut c_void as Encode>::ENCODING;
}

declare_class!(
    struct RegistrationHandler {
        pub authorization_credential: IvarDrop<Option<Id<ASAuthorizationCredential, Shared>>>,
        pub semaphore: GCDSemaphore,
    }

    unsafe impl ClassType for RegistrationHandler {
        type Super = NSObject;
    }

    unsafe impl RegistrationHandler {
        #[method(init)]
        fn init(this: &mut Self) -> Option<&mut Self> {
            let this: Option<&mut Self> = unsafe { msg_send![super(this), init] };

            this.map(|this| {
                Ivar::write(&mut this.semaphore, GCDSemaphore::new());

                this
            })
        }
    }

    unsafe impl ConformsTo<ASAuthorizationControllerDelegate> for RegistrationHandler {
        #[allow(non_snake_case)]
        #[method(authorizationController:didCompleteWithAuthorization:)]
        unsafe fn authorizationController_didCompleteWithAutorization(
            &mut self,
            _controller: &ASAuthorizationController,
            authorization: &ASAuthorization,
        ) {
            trace!("authorizationController:didCompleteWithAuthorization");
            Ivar::write(
                &mut self.authorization_credential,
                Some(authorization.credential()),
            );
            self.semaphore.signal();
        }

        #[allow(non_snake_case)]
        #[method(authorizationController:didCompleteWithError:)]
        unsafe fn authorizationController_didCompleteWithError(
            &self,
            _controller: &ASAuthorizationController,
            error: &NSError,
        ) {
            trace!("authorizationController:didCompleteWithError");
            trace!("{error}");
        }
    }
);

declare_class!(
    struct PresentationContextProvider {}

    unsafe impl ClassType for PresentationContextProvider {
        type Super = NSObject;
    }

    unsafe impl ConformsTo<ASAuthorizationControllerPresentationContextProviding>
        for PresentationContextProvider
    {
        #[allow(non_snake_case)]
        #[method(presentationAnchorForAuthorizationController:)]
        unsafe fn presentationAnchorForAuthorizationController(
            &self,
            _controller: &ASAuthorizationController,
        ) -> *mut ASPresentationAnchor {
            // TODO: this is a hacky workaround until we can return [Id<_,_>]  from within the [cdeclare_class!] macro
            trace!("giving presentation anchor");
            let window = match NSApplication::sharedApplication().mainWindow() {
                Some(window) => window,
                None => {
                    trace!("had no main application window, providing one now");
                    let obj = NSWindow::alloc();
                    icrate::AppKit::NSWindow::initWithContentRect_styleMask_backing_defer(
                        obj,
                        NSRect::new(CGPoint::ZERO, CGSize::new(300., 300.)),
                        NSWindowStyleMaskTitled
                            | NSWindowStyleMaskClosable
                            | NSWindowStyleMaskResizable
                            | NSWindowStyleMaskMiniaturizable,
                        NSBackingStoreBuffered,
                        false,
                    )
                }
            };
            window.center();
            window.setBackgroundColor(Some(&NSColor::whiteColor()));
            window.orderFrontRegardless();
            Id::as_mut_ptr(&mut Id::from_shared(Id::into_super(Id::into_super(window))))
        }
    }
);

impl RegistrationHandler {
    pub fn new() -> Id<Self, Owned> {
        unsafe { msg_send_id![Self::alloc(), init] }
    }
}

impl PresentationContextProvider {
    pub fn new() -> Id<Self, Owned> {
        unsafe { msg_send_id![Self::alloc(), init] }
    }
}

impl AuthenticatorBackend for Macos {
    fn perform_register(
        &mut self,
        origin: Url,
        options: PublicKeyCredentialCreationOptions,
        _timeout_ms: u32,
    ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        trace!("perform register");
        let relying_party_id = NSString::from_str(&origin.as_str());
        let challenge = NSData::with_bytes(options.challenge.as_ref());
        let security_key_provider = {
            let obj = ASAuthorizationSecurityKeyPublicKeyCredentialProvider::alloc();
            unsafe {
                ASAuthorizationSecurityKeyPublicKeyCredentialProvider::initWithRelyingPartyIdentifier(obj, &relying_party_id)
            }
        };
        let display_name = NSString::from_str(&options.user.display_name);
        let name = NSString::from_str(&options.user.name);
        let user_id = NSData::with_bytes(options.user.id.as_ref());
        let security_key_request = unsafe {
            security_key_provider
                .createCredentialRegistrationRequestWithChallenge_displayName_name_userID(
                    &challenge,
                    &display_name,
                    &name,
                    &user_id,
                )
        };
        // TODO: we should be able to use [as_protocol] here, but for some reason [ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest] doesn't implement [ConformsTo<ASAuthorizationPublicKeyCredentialRegistration>]
        let credential_parameters = {
            let obj = ASAuthorizationPublicKeyCredentialParameters::alloc();
            unsafe {
                ASAuthorizationPublicKeyCredentialParameters::initWithAlgorithm(
                    obj,
                    ASCOSEAlgorithmIdentifierES256,
                )
            }
        };
        let credential_parameters = NSArray::from_slice(&[credential_parameters]);
        unsafe { security_key_request.setCredentialParameters(&credential_parameters) };
        let auth_controller = {
            let obj = ASAuthorizationController::alloc();
            let key_requests = NSArray::from_slice(&[Id::into_super(security_key_request)]);
            unsafe {
                ASAuthorizationController::initWithAuthorizationRequests(obj, key_requests.as_ref())
            }
        };

        let mut registration_handler = RegistrationHandler::new();

        let presentation_context_provider = PresentationContextProvider::new();

        // TODO: set [delegate] and [presentationContextProvider]
        unsafe { auth_controller.setDelegate(Some(registration_handler.as_protocol())) };
        let conforms_to = Class::get("RegistrationHandler")
            .unwrap()
            .conforms_to(Protocol::get("ASAuthorizationControllerDelegate").unwrap());
        trace!(?conforms_to);
        unsafe {
            let delegate = auth_controller.delegate().is_some();
            trace!(?delegate);
        };
        unsafe {
            auth_controller
                .setPresentationContextProvider(Some(presentation_context_provider.as_protocol()))
        };

        unsafe { auth_controller.performRequests() };

        trace!("going to start runloop");

        #[cfg(feature = "macos")]
        trace!("going to run application");
        unsafe { NSApplication::sharedApplication().run() };

        trace!("about to wait for semaphore");

        registration_handler.semaphore.wait();

        trace!("finished waiting for semaphore");

        let credential: Id<ASAuthorizationCredential, _> = registration_handler
            .authorization_credential
            .take()
            .unwrap();

        //    downcast into the sole implementor of the protocol
        let credential: Id<ASPublicKeyCredential, _> = unsafe { Id::cast(credential) };

        let raw_id = unsafe { &credential.credentialID() }.bytes().to_vec();
        let client_data_json = unsafe { credential.rawClientDataJSON() }.bytes().to_vec();

        let credential: Id<ASAuthorizationPublicKeyCredentialRegistration, Shared> =
            unsafe { Id::cast(credential) };

        let attestation_object = unsafe { credential.rawAttestationObject() }
            // TODO: use an actual webauthn error here
            .ok_or(WebauthnCError::InvalidAttestation)?
            .bytes()
            .to_vec();

        let raw_id = Base64UrlSafeData(raw_id);

        Ok(RegisterPublicKeyCredential {
            id: raw_id.to_string(),
            raw_id,
            type_: String::from("public-key"),
            extensions: Default::default(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData(attestation_object),
                client_data_json: Base64UrlSafeData(client_data_json),
                // TODO: maybe we can get the transport from somewhere?
                transports: None,
            },
        })
    }

    fn perform_auth(
        &mut self,
        _origin: Url,
        _options: PublicKeyCredentialRequestOptions,
        _timeout_ms: u32,
    ) -> Result<PublicKeyCredential, WebauthnCError> {
        unimplemented!()
    }
}
