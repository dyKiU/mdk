// Compile-only MainActor preview bridge hypothesis. Never execute this capsule.
import AVFoundation
import Foundation
import Synchronization
import UIKit

nonisolated final class CheckedCaptureOwner: Sendable {
    private let session = Mutex(AVCaptureSession())

    @MainActor
    fileprivate func configureAndMakePreview() -> AVCaptureVideoPreviewLayer {
        session.withLock { protectedSession in
            protectedSession.beginConfiguration()
            protectedSession.sessionPreset = .high
            let layer = AVCaptureVideoPreviewLayer(session: protectedSession)
            protectedSession.commitConfiguration()
            return layer
        }
    }

    func start() {
        session.withLock { $0.startRunning() }
    }

    func stop() {
        session.withLock { protectedSession in
            if protectedSession.isRunning {
                protectedSession.stopRunning()
            }
        }
    }
}

@MainActor
private final class MainActorPreviewBridge {
    private let owner: CheckedCaptureOwner
    private let preview: AVCaptureVideoPreviewLayer
    private let queue = DispatchQueue(label: "diagnostic.capture-owner.preview-bridge")

    init() {
        let owner = CheckedCaptureOwner()
        self.owner = owner
        self.preview = owner.configureAndMakePreview()
    }

    func mountAndLayout(in view: UIView) {
        view.layer.addSublayer(preview)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
    }

    func enqueueStartThenStop() {
        let owner = owner
        queue.async { owner.start() }
        queue.async { owner.stop() }
    }
}

private func requireCheckedSendable<T: Sendable>(_ value: T) {}

@MainActor
private func compileOnlyConsumer(view: UIView) {
    requireCheckedSendable(CheckedCaptureOwner())
    let bridge = MainActorPreviewBridge()
    bridge.mountAndLayout(in: view)
    bridge.enqueueStartThenStop()
}
