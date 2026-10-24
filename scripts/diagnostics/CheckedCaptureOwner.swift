// Compile-only AVFoundation isolation probe. Never execute this capsule.
import AVFoundation
import Foundation
import Synchronization
import UIKit

nonisolated final class CheckedCaptureOwner: Sendable {
    private let session = Mutex(AVCaptureSession())

    @MainActor
    func configureAndMakePreview() -> AVCaptureVideoPreviewLayer {
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

private func requireCheckedSendable<T: Sendable>(_ value: T) {}

@MainActor
private func compileOnlyConsumer() {
    let owner = CheckedCaptureOwner()
    requireCheckedSendable(owner)
    let preview = owner.configureAndMakePreview()
    requireCheckedSendable(preview)
    preview.videoGravity = .resizeAspectFill
    preview.frame = CGRect(x: 0, y: 0, width: 320, height: 480)
    let queue = DispatchQueue(label: "diagnostic.capture-owner.typeprobe")
    queue.async { owner.start() }
    queue.async { owner.stop() }
}
