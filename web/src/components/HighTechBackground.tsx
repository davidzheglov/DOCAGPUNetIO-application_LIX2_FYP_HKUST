import { Canvas, useFrame } from "@react-three/fiber";
import { useMemo, useRef } from "react";
import * as THREE from "three";

function SignalField() {
  const group = useRef<THREE.Group>(null);
  const particles = useMemo(() => {
    const positions = new Float32Array(260 * 3);
    for (let i = 0; i < 260; i += 1) {
      positions[i * 3] = (Math.random() - 0.5) * 18;
      positions[i * 3 + 1] = (Math.random() - 0.5) * 9;
      positions[i * 3 + 2] = (Math.random() - 0.5) * 12;
    }
    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    return geometry;
  }, []);

  const lanes = useMemo(() => {
    const positions = new Float32Array([
      -7, -1.8, 0, -3.2, -0.5, 0,
      -3.2, -0.5, 0, 0.4, 0.4, 0,
      0.4, 0.4, 0, 4.6, 0.1, 0,
      -6, 2.1, -1.5, -1.2, 1.2, -0.7,
      -1.2, 1.2, -0.7, 5.6, 1.7, -1.1,
    ]);
    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    return geometry;
  }, []);

  useFrame(({ clock }) => {
    if (!group.current) return;
    group.current.rotation.y = Math.sin(clock.elapsedTime * 0.12) * 0.16;
    group.current.rotation.x = Math.cos(clock.elapsedTime * 0.09) * 0.04;
  });

  return (
    <group ref={group}>
      <points geometry={particles}>
        <pointsMaterial size={0.028} color="#58f6d7" transparent opacity={0.62} />
      </points>
      <lineSegments geometry={lanes}>
        <lineBasicMaterial color="#7dd3fc" transparent opacity={0.45} />
      </lineSegments>
      <mesh position={[-4.8, -1.1, 0]} rotation={[0.7, 0.2, 0.6]}>
        <torusGeometry args={[0.72, 0.018, 12, 80]} />
        <meshBasicMaterial color="#7dd3fc" transparent opacity={0.36} />
      </mesh>
      <mesh position={[0.2, 0.35, 0]} rotation={[0.9, -0.4, 0.2]}>
        <torusGeometry args={[0.98, 0.02, 12, 96]} />
        <meshBasicMaterial color="#7cf7a4" transparent opacity={0.35} />
      </mesh>
      <mesh position={[5.2, 0.1, 0]} rotation={[0.65, 0.55, -0.2]}>
        <torusGeometry args={[0.82, 0.018, 12, 96]} />
        <meshBasicMaterial color="#f6c76d" transparent opacity={0.35} />
      </mesh>
    </group>
  );
}

export function HighTechBackground() {
  return (
    <div className="background-canvas" aria-hidden="true">
      <Canvas camera={{ position: [0, 0, 8], fov: 48 }} dpr={[1, 1.5]}>
        <color attach="background" args={["#05070a"]} />
        <SignalField />
      </Canvas>
    </div>
  );
}
